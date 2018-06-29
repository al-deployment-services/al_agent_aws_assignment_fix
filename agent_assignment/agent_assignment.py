from lib import al_ci_client
from lib import al_cd_client
from datetime import datetime
import time
import requests
import logging
import json
import boto3
import os
from base64 import b64decode
from botocore.exceptions import ClientError
from copy import deepcopy

from requests.packages.urllib3.exceptions import InsecureRequestWarning
#suppres warning for certificate
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOG_LEVEL=logging.INFO
logging.basicConfig(format='%(message)s')
logger = logging.getLogger(__name__)
logger.setLevel(LOG_LEVEL)

HEADERS = {'content-type': 'application/json'}

def write_to_s3(args, payload):
    try:
        s3 = boto3.resource('s3')
        object = s3.Object(args['s3_bucket'], str(datetime.now().strftime('%Y-%m-%d')) + '/' + args['file_name'])
        object.put(Body=payload.encode())
        return True

    except ClientError as e:
        return False

def cd_get_env_cid(args):
    myCI = al_ci_client.CloudInsight(args)
    query_args={}
    query_args['type'] = 'aws'
    query_args['defender_support'] = 'true'
    return myCI.get_environments_by_cid_custom(query_args)

#Get all child under parent
def find_all_child(args):
    myCI = al_ci_client.CloudInsight(args)
    CID_DICT = myCI.get_all_child()
    COMBINED_PLAN = []

    #Grab Parent CID and search per Environment
    logger.info("### PROCESSING PARENT CID ###")
    COMBINED_PLAN.append(monitor_per_cid(args))

    #Loop through the child and find all private IP's
    if len(CID_DICT["accounts"]) > 0:
        logger.info("### PROCESSING CHILD CID ###")

    for CHILD in CID_DICT["accounts"]:
        child_args = deepcopy(args)
        child_args["acc_id"] = CHILD["id"]
        CHILD_PLAN = monitor_per_cid(child_args)
        if CHILD_PLAN['environments']:
            COMBINED_PLAN.append(CHILD_PLAN)

    logger.info("\nAll CID results: {0}".format(json.dumps(COMBINED_PLAN, sort_keys=True, indent=2)))

    FINAL_FILE_NAME = str(time.strftime("%Y%m%d-%H%M%S")) + "_final_output.json"
    args["file_name"] = FINAL_FILE_NAME

    write_to_s3(args, json.dumps(COMBINED_PLAN, indent=2, sort_keys=True, ensure_ascii=True))
    logger.info("Results stored in: {0}".format(FINAL_FILE_NAME))

def monitor_per_cid(args):
    args["log_header"] = "CID:{0}".format(args['acc_id'])
    cd_environments = cd_get_env_cid(args)
    logger.info("{0} - Deployment Env ID found: {1}".format(args["log_header"], cd_environments["count"]))

    FIX_PLAN = {}
    FIX_PLAN['cid'] = args['acc_id']
    FIX_PLAN['environments'] = []
    if cd_environments:
        #Defender API only have logical group up to CID level, and has no awareness of Deployment/EnvironmentID
        #Pull the list of all AL-Agent in orphan status and group by AWS ID and VPC
        ORPHAN_PHOST = group_orphan_protectedhost(args)
        ASSIGNMENT_POLICY = group_assignment_per_cid(args)

        for env in cd_environments["environments"]:

            logger.info("{0} ENV:{1} AWS:{2} NAME:{3} checking al-agent assignment policy status".format(args['log_header'], env['id'], env["type_id"], env["name"].encode('utf-8', 'ignore')))
            if env['type_id'] in ORPHAN_PHOST:
                env_args = deepcopy(args)
                env_args["env_id"] = env["id"]
                env_args["env_name"] = env["name"]
                env_args["aws_id"] = env["type_id"]
                env_args["log_header"] = "{0} ENV:{1} AWS:{2} NAME:{3}".format(env_args['log_header'], env_args['env_id'], env_args["aws_id"], env_args["env_name"])
                env_assignment_status = {}
                env_assignment_status['env_id'] = env['id']
                env_assignment_status['env_name'] = env["name"]
                env_assignment_status['aws_id'] = env["type_id"]
                env_assignment_status['result'] = fix_agent_assignment(env_args, ORPHAN_PHOST[env_args['aws_id']], ASSIGNMENT_POLICY)

                logger.info("{0} ENV:{1} AWS:{2} NAME:{3} status: {4}".format(env_args['log_header'], env_args['env_id'], env_args["aws_id"], env_args["env_name"], json.dumps(env_assignment_status,indent=2)))
                #logger.info()
                FIX_PLAN['environments'].append(env_assignment_status)
            else:
                logger.info("{0} ENV:{1} AWS:{2} NAME:{3} status: no orphaned PHOST found".format(args['log_header'], env['id'], env["type_id"], env["name"]))
    return FIX_PLAN

def get_orphan_protectedhost(args):
    query_args={}
    query_args['config.collection_method'] = 'agent'
    query_args['status.status'] = 'error,new'
    query_args['type'] = 'host'
    myCD = al_cd_client.CloudDefender(args)
    return myCD.get_phost_custom(query_args)

def get_assignment_policy(args):
    query_args={}
    query_args['type'] = 'appliance_assignment'
    myCD = al_cd_client.CloudDefender(args)
    return myCD.get_policy(query_args)

def update_protectedhost_assignment(args):
    myCD = al_cd_client.CloudDefender(args)
    PAYLOAD = '{"protectedhost": { "appliance": { "policy": { "id":"' + args['policy_id'] + '"}}}}'

    if args['dry_run'] == 'False':
        REQUEST = myCD.update_phost(phost_id=args['phost_id'], payload=PAYLOAD)
        if REQUEST.status_code == 200:
            return "Success"
        else:
            return REQUEST.text
    else:
        return "Dry Run Test"

def group_orphan_protectedhost(args):
    ORPHAN_PHOST = get_orphan_protectedhost(args)
    #Group all PHOST by it's AWS Account and VPC
    RESULT = {}
    if 'protectedhosts' in ORPHAN_PHOST:
        for PHOST in ORPHAN_PHOST['protectedhosts']:
            if 'metadata' in PHOST['protectedhost']:
                if 'ec2_account_id' in PHOST['protectedhost']['metadata']:
                    if 'ec2_vpc' in PHOST['protectedhost']['metadata']:
                        aws_id = PHOST['protectedhost']['metadata']['ec2_account_id']
                        vpc_id = PHOST['protectedhost']['metadata']['ec2_vpc'][0]

                        #the absent of appliance or policy field indicate that the al-agent is in orphan status
                        if 'appliance' not in PHOST['protectedhost'] or 'policy' not in PHOST['protectedhost']['appliance']:
                            if aws_id in RESULT:
                                if vpc_id in RESULT[aws_id]:
                                    RESULT[aws_id][vpc_id].append(PHOST['protectedhost'])
                                else:
                                    RESULT[aws_id][vpc_id] = []
                                    RESULT[aws_id][vpc_id].append(PHOST['protectedhost'])
                            else:
                                RESULT[aws_id] = {}
                                RESULT[aws_id][vpc_id] = []
                                RESULT[aws_id][vpc_id].append(PHOST['protectedhost'])
                        #al-agent has assignment but still in error - possibly human error
                        elif 'appliance' in PHOST['protectedhost'] or 'policy' in PHOST['protectedhost']['appliance']:
                            if aws_id in RESULT:
                                if vpc_id in RESULT[aws_id]:
                                    RESULT[aws_id][vpc_id].append(PHOST['protectedhost'])
                                else:
                                    RESULT[aws_id][vpc_id] = []
                                    RESULT[aws_id][vpc_id].append(PHOST['protectedhost'])
                            else:
                                RESULT[aws_id] = {}
                                RESULT[aws_id][vpc_id] = []
                                RESULT[aws_id][vpc_id].append(PHOST['protectedhost'])
                    else:
                        logger.info("{0} AWS AL-Agent found without VPC info: {1}".format(args['log_header'], PHOST['protectedhost']))
                else:
                    logger.info("{0} Non AWS AL-Agent found : {1}".format(args['log_header'], PHOST['protectedhost']))
    else:
        logger.info("{0} No AL-Agent found".format(args['log_header']))
    return RESULT

def fix_agent_assignment(args, phost_lists, assignment_list):
    #Find assignment policy that matches the VPC ID
    for phost_vpc in phost_lists:
        if phost_vpc in assignment_list:
            logger.info("{0} VPC:{1} - assignment policy matches found:".format(args["log_header"], phost_vpc))
            for policy_id in assignment_list[phost_vpc]:
                logger.info("{0} VPC:{1} - Assignment Policy ID: {2}".format(args["log_header"], phost_vpc, policy_id))

            #We might find more than one assignment that matches, by default will take the first one from the list
            args['policy_id'] = assignment_list[phost_vpc][0]

            counter=0
            for phost in phost_lists[phost_vpc]:
                args['phost_id'] = phost["id"]
                RESPONSE = update_protectedhost_assignment(args)
                logger.info("{0} VPC:{1} PHOST_ID:{2} PHOST_NAME:{3} status:{4}".format(args["log_header"], phost_vpc, phost["id"], phost["name"], RESPONSE))
                phost_lists[phost_vpc][counter] = {}
                phost_lists[phost_vpc][counter]['phost_id'] = phost["id"]
                phost_lists[phost_vpc][counter]['phost_name'] = phost["name"]
                phost_lists[phost_vpc][counter]['status'] = RESPONSE
                counter=counter+1
        else:
            logger.info("{0} VPC:{1} - no assignment policy matches found".format(args["log_header"], phost_vpc))
            counter=0
            for phost in phost_lists[phost_vpc]:
                phost_lists[phost_vpc][counter] = {}
                phost_lists[phost_vpc][counter]['phost_id'] = phost["id"]
                phost_lists[phost_vpc][counter]['phost_name'] = phost["name"]
                phost_lists[phost_vpc][counter]['status'] = "no match VPC ID found"
                counter=counter+1

    return phost_lists

def group_assignment_per_cid(args):
    ASSIGNMENT_POLICY = get_assignment_policy(args)

    #Assignment policy did not contain info about AWS account, so group will be done by VPC ID
    RESULT = {}
    if 'policies' in ASSIGNMENT_POLICY:
        for POLICY in ASSIGNMENT_POLICY['policies']:
            if "default_for" in POLICY['policy']:
                if 'vpc' in POLICY['policy']['default_for']:
                    #check if this is assignment policy for peering (multiple VPCs)
                    if type(POLICY['policy']['default_for']['vpc']) is list:
                        if len(POLICY['policy']['default_for']['vpc']) > 1:
                            for vpc_id in POLICY['policy']['default_for']['vpc']:
                                if vpc_id in RESULT:
                                    RESULT[vpc_id].append(POLICY['policy']['id'])
                                else:
                                    RESULT[vpc_id] = []
                                    RESULT[vpc_id].append(POLICY['policy']['id'])
                        else:
                            vpc_id = POLICY['policy']['default_for']['vpc'][0]
                            if vpc_id in RESULT:
                                RESULT[vpc_id].append(POLICY['policy']['id'])
                            else:
                                RESULT[vpc_id] = []
                                RESULT[vpc_id].append(POLICY['policy']['id'])
                    else:
                        vpc_id = POLICY['policy']['default_for']['vpc']
                        if vpc_id in RESULT:
                            RESULT[vpc_id].append(POLICY['policy']['id'])
                        else:
                            RESULT[vpc_id] = []
                            RESULT[vpc_id].append(POLICY['policy']['id'])
                else:
                    logger.info("{0} Non AWS Assignment found, policy ID : {1}".format(args['log_header'], POLICY['policy']['id']))
    else:
        logger.info("{0} No Assignment policy found".format(args['log_header']))

    return RESULT

def lambda_handler(event, context):
    if os.environ["DC"] == "DENVER":
        event["yarp"] = "api.cloudinsight.alertlogic.com"
        event["defender_yarp"] = "https://publicapi.alertlogic.net/api/tm/v1/"
        event["cd_yarp"] = "publicapi.alertlogic.net/api"
    elif os.environ["DC"] == "ASHBURN":
        event["yarp"] = "api.cloudinsight.alertlogic.com"
        event["defender_yarp"] = "https://publicapi.alertlogic.com/api/tm/v1/"
        event["cd_yarp"] = "publicapi.alertlogic.com/api"
    elif os.environ["DC"] == "NEWPORT":
        event["yarp"] = "api.cloudinsight.alertlogic.co.uk"
        event["defender_yarp"] = "https://publicapi.alertlogic.co.uk/api/tm/v1/"
        event["cd_yarp"] = "publicapi.alertlogic.co.uk/api"

    event["output"] = os.environ["OUTPUT"]
    event["user"] = os.environ["USER"]
    event["acc_id"] = os.environ["PARENT_CID"]
    event["dry_run"] = os.environ["DRY_RUN"]
    plaintext = boto3.client('kms').decrypt(CiphertextBlob=b64decode(os.environ["SECRET"]))["Plaintext"]
    event["password"] = json.loads(plaintext)["Password"]
    event["defender_api_key"] = json.loads(plaintext)["DefenderKey"]
    event["cd_key"] = json.loads(plaintext)["DefenderKey"]
    event["s3_bucket"] = os.environ["OUTPUT"]

    if event["type"] == "check_assignment" :
        logger.info("Start Operations : {0} - Event Type: {1}".format(datetime.now(), event['type']))
        find_all_child(event)
        logger.info("End Operations : {0} - Event Type: {1}".format(datetime.now(), event['type']))
    else:
        logger.error("Event type not supported: {0}".format(event["type"]))
