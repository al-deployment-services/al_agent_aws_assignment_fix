from CIAuth import CIAuth

class LauncherClient(CIAuth):
    def __init__(self, args):
        self.service = "launcher"
        CIAuth.__init__(self, args)

    def troubleshooting(self, acc_id, env_id, endpoint, region, vpc_id=None):
        url = [acc_id, env_id, endpoint]
        query =  "?region=%s" % region
        if vpc_id:
            query += "&vpc_id=%s" % vpc_id
        url.append(query)
        return self.query(self.service, url, version="v1_troubleshooting")

    def get_deployment_status(self, acc_id, env_id, vpc_key = None):
        result = self.get_deployment_status_raw(acc_id, env_id)
        if vpc_key == None:
            return result
        else:
            self.get_vpc_deployment_status(acc_id, env_id, vpc_key, result)

    def get_vpc_deployment_status(self, acc_id, env_id, vpc_key, raw_deployment_status):
        regions = raw_deployment_status['scope']
        key = acc_id + ":" + env_id + ":" + vpc_key
        # ""134232844:5CEC044D-3F47-491F-B227-7DF1DF13A375:/aws/us-west-2/vpc/vpc-350e7d52"
        for region in regions:
            for vpc in region['scope']:
                if vpc['key'] == key:
                    return vpc
        return None

    def get_deployment_status_raw(self, acc_id, env_id):
        return self.query(self.service, [acc_id, "environments", env_id])

    def get_resources(self, acc_id, env_id):
        return self.query(self.service, [acc_id, env_id, "resources"])

    def get_access_report_by_appliance(self, acc_id, env_id, appliance_id):
        return self.query(self.service, [acc_id, env_id, "access_report", "appliance", appliance_id], version="v1_remediation")

    def get_access_report_by_instance(self, acc_id, env_id, region, instance):
        return self.query(self.service, [acc_id, env_id, "access_report", "instance", region, instance], version="v1_remediation")

    def get_ami_map(self):
        return self.query(self.service, ["amis/scan"])

    def get_flat_ami_map(self):
        ami_map = self.get_ami_map()
        flat_ami_map = []
        for region, region_amis in ami_map.iteritems():
            ami_id_list = [ami['ami-id'] for ami in region_amis]
            flat_ami_map = flat_ami_map + ami_id_list

        return flat_ami_map

    def get_redeploy(self, acc_id, env_id, vpc_key = None, hard = False):
        if vpc_key:
            env_id += "?hard=true&vpc_key="+vpc_key
        elif hard:
            env_id += "?hard=true"

        return self.query(self.service, [acc_id, "redeploy", env_id], version="v1_remediation", json_response=False)

    def get_check_token(self, token):
        return self.query(self.service, ["check_token", token], version="v1_remediation")

    def get_autoscaling_states(self, acc_id, env_id):
        return self.query(self.service, [acc_id, env_id, "autoscaling_states"], version="v1_remediation")

    def set_tuning(self, acc_id, env_id, body, vpc_key = None):
        return self.tuning_query(acc_id, env_id, method='put', payload=body, vpc_key=vpc_key)

    def delete_tuning(self, acc_id, env_id, option, vpc_key = None):
        return self.tuning_query(acc_id, env_id, method='delete', option=option, vpc_key=vpc_key)

    def get_tuning(self, acc_id, env_id, vpc_key = None):
        return self.tuning_query(acc_id, env_id, vpc_key=vpc_key)

    def tuning_query(self, acc_id, env_id, method='get', option=None, payload=None, vpc_key=None):
        query_param = {}
        if vpc_key:
            query_param['vpc_key'] = vpc_key

        version = "v1_remediation"
        url = [acc_id, env_id, "tuning"]
        if option:
            url.append(option)

        return self.raw_query(self.service, url, version = version, method=method, payload=payload, query=query_param)
