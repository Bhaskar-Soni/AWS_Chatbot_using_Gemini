import threading
import boto3
import streamlit as st
from cryptography.fernet import Fernet
#from menu import custom_menu
from config import CREDENTIALS_FILE, ENCRYPTION_KEY_FILE

# Display the custom menu
#custom_menu()

# Function to load encryption key
def load_key():
    with open(ENCRYPTION_KEY_FILE, 'rb') as f:
        return f.read()

# Initialize Fernet cipher suite with loaded encryption key
key = load_key()
cipher_suite = Fernet(key)

# Function to decrypt data
def decrypt_data(encrypted_data):
    decrypted_data = cipher_suite.decrypt(encrypted_data.encode())
    return decrypted_data.decode()

# Function to load credentials from file and decrypt them
def load_credentials():
    with open(CREDENTIALS_FILE, 'r') as f:
        lines = f.readlines()
        access_key = decrypt_data(lines[0].split(': ')[1].strip())
        secret_key = decrypt_data(lines[1].split(': ')[1].strip())
        region = lines[2].split(': ')[1].strip()
        return access_key, secret_key, region

# Load and decrypt credentials
aws_access_key_id, aws_secret_access_key, region = load_credentials()

def count_running_services(aws_access_key_id, aws_secret_access_key, region):
    counts = {}

    try:
        session = boto3.Session(
            region_name=region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key
        )

        def get_running_instances():
            nonlocal counts
            ec2_client = session.client('ec2')
            response = ec2_client.describe_instances(Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
            counts['Running EC2 Instances'] = len(response['Reservations'])

        def get_running_rds_instances():
            nonlocal counts
            rds_client = session.client('rds')
            response = rds_client.describe_db_instances()
            counts['Running RDS Instances'] = sum(1 for db_instance in response['DBInstances'] if db_instance['DBInstanceStatus'] == 'available')

        def get_running_ecs_clusters():
            nonlocal counts
            ecs_client = session.client('ecs')
            response = ecs_client.list_clusters()
            counts['Running ECS Clusters'] = len(response['clusterArns'])

        def get_s3_buckets():
            nonlocal counts
            s3_client = session.client('s3')
            response = s3_client.list_buckets()
            counts['S3 Buckets'] = len(response['Buckets'])

        def get_lambda_functions():
            nonlocal counts
            lambda_client = session.client('lambda')
            response = lambda_client.list_functions()
            counts['Lambda Functions'] = len(response['Functions'])

        def get_sqs_queues():
            nonlocal counts
            try:
                sqs_client = session.client('sqs')
                response = sqs_client.list_queues()
                if 'QueueUrls' in response:
                    counts['SQS Queues'] = len(response['QueueUrls'])
                else:
                    counts['SQS Queues'] = 0
            except Exception as e:
                print(f"An error occurred while getting SQS queues: {e}")

        def get_sns_client():
            nonlocal counts
            sns_client = session.client('sns')
            response = sns_client.list_topics()
            counts['SNS Topics'] = len(response['Topics'])

        def get_iam_client():
            nonlocal counts
            iam_client = session.client('iam')
            response = iam_client.list_users()
            counts['IAM Users'] = len(response['Users'])

        def get_cloudwatch_alarms():
            nonlocal counts
            cloudwatch_client = session.client('cloudwatch')
            response = cloudwatch_client.describe_alarms()
            counts['CloudWatch Alarms'] = len(response['MetricAlarms'])

        def get_dynamodb_tables():
            nonlocal counts
            dynamodb_client = session.client('dynamodb')
            response = dynamodb_client.list_tables()
            counts['DynamoDB Tables'] = len(response['TableNames'])

        def get_eb_environments():
            nonlocal counts
            elasticbeanstalk_client = session.client('elasticbeanstalk')
            response = elasticbeanstalk_client.describe_environments()
            counts['Elastic Beanstalk Environments'] = len(response['Environments'])

        def get_elbs():
            nonlocal counts
            elb_client = session.client('elbv2')
            response = elb_client.describe_load_balancers()
            counts['ELBs'] = len(response['LoadBalancers'])

        def get_vpcs():
            nonlocal counts
            ec2_client = session.client('ec2')
            response = ec2_client.describe_vpcs()
            counts['VPCs'] = len(response['Vpcs'])

        def get_ecs_clusters():
            nonlocal counts
            ecs_client = session.client('ecs')
            response = ecs_client.list_clusters()
            counts['ECS Clusters'] = len(response['clusterArns'])

        def get_eks_clusters():
            nonlocal counts
            eks_client = session.client('eks')
            response = eks_client.list_clusters()
            counts['EKS Clusters'] = len(response['clusters'])

        def get_efs_file_systems():
            nonlocal counts
            efs_client = session.client('efs')
            response = efs_client.describe_file_systems()
            counts['EFS File Systems'] = len(response['FileSystems'])

        def get_es_domains():
            nonlocal counts
            es_client = session.client('es')
            response = es_client.list_domain_names()
            counts['Elasticsearch Domains'] = len(response['DomainNames'])

        def get_apigateway_apis():
            nonlocal counts
            apigateway_client = session.client('apigateway')
            response = apigateway_client.get_rest_apis()
            counts['API Gateway APIs'] = len(response['items'])

        def get_stepfunctions_state_machines():
            nonlocal counts
            stepfunctions_client = session.client('stepfunctions')
            response = stepfunctions_client.list_state_machines()
            counts['Step Functions State Machines'] = len(response['stateMachines'])

        def get_glue_databases():
            nonlocal counts
            glue_client = session.client('glue')
            response = glue_client.get_databases()
            counts['Glue Databases'] = len(response['DatabaseList'])

        def get_kinesis_streams():
            nonlocal counts
            kinesis_client = session.client('kinesis')
            response = kinesis_client.list_streams()
            counts['Kinesis Streams'] = len(response['StreamNames'])

        def get_athena_workgroups():
            nonlocal counts
            athena_client = session.client('athena')
            response = athena_client.list_work_groups()
            counts['Athena Workgroups'] = len(response['WorkGroups'])

        def get_redshift_clusters():
            nonlocal counts
            redshift_client = session.client('redshift')
            response = redshift_client.describe_clusters()
            counts['Redshift Clusters'] = len(response['Clusters'])

        def get_autoscaling_groups():
            nonlocal counts
            autoscaling_client = session.client('autoscaling')
            response = autoscaling_client.describe_auto_scaling_groups()
            counts['Auto Scaling Groups'] = len(response['AutoScalingGroups'])

        def get_ecr_repositories():
            nonlocal counts
            ecr_client = session.client('ecr')
            response = ecr_client.describe_repositories()
            counts['ECR Repositories'] = len(response['repositories'])

        def get_elastictranscoder_pipelines():
            nonlocal counts
            elastictranscoder_client = session.client('elastictranscoder')
            response = elastictranscoder_client.list_pipelines()
            counts['Elastic Transcoder Pipelines'] = len(response['Pipelines'])

        def get_msk_clusters():
            nonlocal counts
            msk_client = session.client('kafka')
            response = msk_client.list_clusters()
            counts['MSK Clusters'] = len(response['ClusterInfoList'])

        def get_emr_clusters():
            nonlocal counts
            emr_client = session.client('emr')
            response = emr_client.list_clusters()
            counts['EMR Clusters'] = len(response['Clusters'])

        def get_neptune_clusters():
            nonlocal counts
            neptune_client = session.client('neptune')
            response = neptune_client.describe_db_clusters()
            counts['Neptune Clusters'] = len(response['DBClusters'])

        def get_directconnect_connections():
            nonlocal counts
            directconnect_client = session.client('directconnect')
            response = directconnect_client.describe_connections()
            counts['Direct Connect Connections'] = len(response['connections'])

        def get_managedblockchain_networks():
            nonlocal counts
            managedblockchain_client = session.client('managedblockchain')
            response = managedblockchain_client.list_networks()
            counts['Managed Blockchain Networks'] = len(response['Networks'])

        def get_elasticinference_accelerators():
            nonlocal counts
            elasticinference_client = session.client('elastic-inference')
            response = elasticinference_client.describe_accelerators()
            counts['Elastic Inference Accelerators'] = len(response['acceleratorSet'])

        def get_workspaces():
            nonlocal counts
            workspaces_client = session.client('workspaces')
            response = workspaces_client.describe_workspaces()
            counts['WorkSpaces'] = len(response['Workspaces'])

        def get_secrets():
            nonlocal counts
            secrets_client = session.client('secretsmanager')
            response = secrets_client.list_secrets()
            counts['Secrets Manager Secrets'] = len(response['SecretList'])

        def get_keys():
            nonlocal counts
            kms_client = session.client('kms')
            response = kms_client.list_keys()
            counts['KMS Keys'] = len(response['Keys'])

        def get_queues():
            nonlocal counts
            try:
                sqs_client = session.client('sqs')
                response = sqs_client.list_queues()
                if 'QueueUrls' in response:
                    counts['SQS Queues'] = len(response['QueueUrls'])
                else:
                    counts['SQS Queues'] = 0
            except Exception as e:
                print(f"An error occurred while getting SQS queues: {e}")

        def get_topics():
            nonlocal counts
            sns_client = session.client('sns')
            response = sns_client.list_topics()
            counts['SNS Topics'] = len(response['Topics'])

        def get_instances():
            nonlocal counts
            ec2_client = session.client('ec2')
            response = ec2_client.describe_instances()
            counts['EC2 Instances'] = len(response['Reservations'])

        def get_volumes():
            nonlocal counts
            ec2_client = session.client('ec2')
            response = ec2_client.describe_volumes()
            counts['EBS Volumes'] = len(response['Volumes'])

        def get_snapshots():
            nonlocal counts
            ec2_client = session.client('ec2')
            response = ec2_client.describe_snapshots()
            counts['EBS Snapshots'] = len(response['Snapshots'])

        def get_security_groups():
            nonlocal counts
            ec2_client = session.client('ec2')
            response = ec2_client.describe_security_groups()
            counts['Security Groups'] = len(response['SecurityGroups'])

        def get_images():
            nonlocal counts
            ec2_client = session.client('ec2')
            response = ec2_client.describe_images(Owners=['self'])
            counts['EC2 AMIs'] = len(response['Images'])

        def get_instances():
            nonlocal counts
            ec2_client = session.client('ec2')
            response = ec2_client.describe_instances()
            counts['EC2 Instances'] = len(response['Reservations'])

        def get_key_pairs():
            nonlocal counts
            ec2_client = session.client('ec2')
            response = ec2_client.describe_key_pairs()
            counts['Key Pairs'] = len(response['KeyPairs'])

        threads = [
            threading.Thread(target=get_running_instances),
            threading.Thread(target=get_running_rds_instances),
            threading.Thread(target=get_running_ecs_clusters),
            threading.Thread(target=get_s3_buckets),
            threading.Thread(target=get_lambda_functions),
            threading.Thread(target=get_sqs_queues),
            threading.Thread(target=get_sns_client),
            threading.Thread(target=get_iam_client),
            threading.Thread(target=get_cloudwatch_alarms),
            threading.Thread(target=get_dynamodb_tables),
            threading.Thread(target=get_eb_environments),
            threading.Thread(target=get_elbs),
            threading.Thread(target=get_vpcs),
            threading.Thread(target=get_ecs_clusters),
            threading.Thread(target=get_eks_clusters),
            threading.Thread(target=get_efs_file_systems),
            threading.Thread(target=get_es_domains),
            threading.Thread(target=get_apigateway_apis),
            threading.Thread(target=get_stepfunctions_state_machines),
            threading.Thread(target=get_glue_databases),
            threading.Thread(target=get_kinesis_streams),
            threading.Thread(target=get_athena_workgroups),
            threading.Thread(target=get_redshift_clusters),
            threading.Thread(target=get_autoscaling_groups),
            threading.Thread(target=get_ecr_repositories),
            threading.Thread(target=get_elastictranscoder_pipelines),
            threading.Thread(target=get_msk_clusters),
            threading.Thread(target=get_emr_clusters),
            threading.Thread(target=get_neptune_clusters),
            threading.Thread(target=get_directconnect_connections),
            threading.Thread(target=get_managedblockchain_networks),
            threading.Thread(target=get_elasticinference_accelerators),
            threading.Thread(target=get_workspaces),
            threading.Thread(target=get_secrets),
            threading.Thread(target=get_keys),
            threading.Thread(target=get_queues),
            threading.Thread(target=get_topics),
            threading.Thread(target=get_instances),
            threading.Thread(target=get_volumes),
            threading.Thread(target=get_snapshots),
            threading.Thread(target=get_security_groups),
            threading.Thread(target=get_images),
            threading.Thread(target=get_key_pairs)
        ]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

    except Exception as e:
        st.error(f"An error occurred: {e}")

    # Filter out services with count 0
    counts = {key: value for key, value in counts.items() if value > 0}

    return counts

def running_services():
    st.title("AWS Service Count")
    st.write("This app displays the count of various AWS services that are currently running.")

    global aws_access_key_id, aws_secret_access_key, region  # Ensure these variables are accessible

    if not aws_access_key_id or not aws_secret_access_key or not region:
        st.error("Credentials or region are not provided.")
        return

    # Automatically start counting services upon running the script
    counts = count_running_services(aws_access_key_id, aws_secret_access_key, region)
    if counts:
        st.subheader("Running AWS Services:")
        for service, count in counts.items():
            st.write(f"- {service}: {count}")

    else:
        st.write("No running services found.")

if __name__ == "__main__":
    running_services()
