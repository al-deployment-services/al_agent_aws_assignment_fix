
# AL-Agent Assignment Policy Fix

This is sample demonstration on how to utilize AlertLogic API in order to fix missing assignment policy for al-agents that may occur due to many situations. This example will utilize AWS Lambda, S3, CloudWatch and SNS. You will be charged for AWS resource deployed from this example.

AlertLogic API end-point used in this demonstration:

* Cloud Insight API (https://console.cloudinsight.alertlogic.com/api/#/)
* Cloud Defender API (https://docs.alertlogic.com/developer/)

## Requirements
* Alert Logic Account ID (CID)
* Alert Logic Cloud Insight credentials (user name and password, or access key and secret key)
* Alert Logic Cloud Defender API Key
* Cloud Defender Deployment in the target CID

## Getting Started
* Use the [CFT template](/cloud_formation) to launch the setup.
* Grab the output SNS topic and subcribe to the topic in order to get warning for Lambda execution error
* The Lambda execute once every 1 hour, modify this rate if necessary
* Check the results in Alert Logic console and verify the orphaned al-agent received the assignment
