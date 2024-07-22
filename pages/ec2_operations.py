import boto3
import paramiko
from paramiko import SSHClient, AutoAddPolicy, RSAKey
from cryptography.fernet import Fernet

# Constants from config.py
from config import CREDENTIALS_FILE, ENCRYPTION_KEY_FILE, PEM_FILE_PATH

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

# Load and decrypt AWS credentials
aws_access_key_id, aws_secret_access_key, region = load_credentials()

# Function to get EC2 instance IP
def get_ec2_instance_ip(instance_id):
    ec2 = boto3.client('ec2',
                       aws_access_key_id=aws_access_key_id,
                       aws_secret_access_key=aws_secret_access_key,
                       region_name=region)

    reservations = ec2.describe_instances(InstanceIds=[instance_id]).get('Reservations')
    for reservation in reservations:
        for instance in reservation['Instances']:
            return instance['PublicIpAddress']
    return None

# Function to check CPUs on the instance
def check_cpus(instance_id, username='ec2-user'):
    instance_ip = get_ec2_instance_ip(instance_id)
    if not instance_ip:
        raise Exception(f"Could not find the instance {instance_id} in the region {region}.")

    ssh = SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(instance_ip, username=username, key_filename=PEM_FILE_PATH)

    stdin, stdout, stderr = ssh.exec_command('nproc')
    output = stdout.read().decode('utf-8').strip()
    ssh.close()

    return f"CPUs: {output}"

# Function to check storage on the instance
def check_storage(instance_id, username='ec2-user'):
    instance_ip = get_ec2_instance_ip(instance_id)
    if not instance_ip:
        raise Exception(f"Could not find the instance {instance_id} in the region {region}.")

    ssh = SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(instance_ip, username=username, key_filename=PEM_FILE_PATH)

    stdin, stdout, stderr = ssh.exec_command('df -h /')
    output = stdout.read().decode('utf-8').strip()
    ssh.close()

    # Split the output into lines and format them
    lines = output.splitlines()
    result = "\n".join(lines)

    return f"Storage:\n{result}"

# Function to check open ports on the instance
def check_open_ports(instance_id, username='ec2-user'):
    instance_ip = get_ec2_instance_ip(instance_id)
    if not instance_ip:
        raise Exception(f"Could not find the instance {instance_id} in the region {region}.")

    ssh = SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(instance_ip, username=username, key_filename=PEM_FILE_PATH)

    stdin, stdout, stderr = ssh.exec_command('netstat -tuln | grep LISTEN')
    output = stdout.read().decode('utf-8').strip()
    ssh.close()

    return f"Open Ports:\n{output}"

# Function to check OS version on the instance
def check_os_version(instance_id, username='ec2-user'):
    instance_ip = get_ec2_instance_ip(instance_id)
    if not instance_ip:
        raise Exception(f"Could not find the instance {instance_id} in the region {region}.")

    ssh = SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(instance_ip, username=username, key_filename=PEM_FILE_PATH)

    stdin, stdout, stderr = ssh.exec_command('cat /etc/os-release')
    output = stdout.read().decode('utf-8').strip()
    ssh.close()

    return output

# Function to check kernel version on the instance
def check_kernel_version(instance_id, username='ec2-user'):
    instance_ip = get_ec2_instance_ip(instance_id)
    if not instance_ip:
        raise Exception(f"Could not find the instance {instance_id} in the region {region}.")

    ssh = SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(instance_ip, username=username, key_filename=PEM_FILE_PATH)

    stdin, stdout, stderr = ssh.exec_command('uname -r')
    output = stdout.read().decode('utf-8').strip()
    ssh.close()

    return f"Kernel Version: {output}"

# Function to check All Users on the instance
def list_users(instance_id, username='ec2-user'):
    instance_ip = get_ec2_instance_ip(instance_id)
    if not instance_ip:
        raise Exception(f"Could not find the instance {instance_id} in the region {region}.")

    ssh = SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(instance_ip, username=username, key_filename=PEM_FILE_PATH)

    stdin, stdout, stderr = ssh.exec_command('cat /etc/passwd')
    output = stdout.read().decode('utf-8').strip()
    ssh.close()

    users = [line.split(':')[0] for line in output.split('\n')]
    return f"**Users on the instance**:\n{', '.join(users)}"

# Function to read first 50 lines of a file
def check_first_n_lines(file_path, n):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            first_n_lines = ''.join(lines[:n])
            return f"**First {n} lines of {file_path}**:\n{first_n_lines}"
    except Exception as e:
        return f"Error: {e}"
    
# Function to read last 50 lines of a file
def check_last_n_lines(file_path, n):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            last_n_lines = ''.join(lines[-n:])
            return f"**Last {n} lines of {file_path}**:\n{last_n_lines}"
    except Exception as e:
        return f"Error: {e}"

# Function to parse RAM output
def parse_ram_output(output):
    lines = output.split('\n')
    ram_info = {}
    for line in lines:
        if line.startswith("Mem:"):
            parts = line.split()
            ram_info['Total'] = parts[1]
            ram_info['Used'] = parts[2]
            ram_info['Free'] = parts[3]
            ram_info['Shared'] = parts[4]
            ram_info['Buff/Cache'] = parts[5]
            ram_info['Available'] = parts[6]
        elif line.startswith("Swap:"):
            parts = line.split()
            ram_info['Swap Total'] = parts[1]
            ram_info['Swap Used'] = parts[2]
            ram_info['Swap Free'] = parts[3]
    return ram_info

# Function to format RAM info
def format_ram_info(ram_info):
    return (
        f"RAM Info:\n"
        f"Total: {ram_info['Total']}\n"
        f"Used: {ram_info['Used']}\n"
        f"Free: {ram_info['Free']}\n"
        f"Shared: {ram_info['Shared']}\n"
        f"Buff/Cache: {ram_info['Buff/Cache']}\n"
        f"Available: {ram_info['Available']}\n"
        f"Swap Total: {ram_info['Swap Total']}\n"
        f"Swap Used: {ram_info['Swap Used']}\n"
        f"Swap Free: {ram_info['Swap Free']}\n"
    )

# Function to check RAM on the instance
def check_ram(instance_id, username='ec2-user'):
    instance_ip = get_ec2_instance_ip(instance_id)
    if not instance_ip:
        raise Exception(f"Could not find the instance {instance_id} in the region {region}.")

    ssh = SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(instance_ip, username=username, key_filename=PEM_FILE_PATH)

    stdin, stdout, stderr = ssh.exec_command('free -h')
    output = stdout.read().decode('utf-8')
    ssh.close()

    ram_info = parse_ram_output(output)
    formatted_output = format_ram_info(ram_info)
    return formatted_output

# Function to list EC2 instances
def list_instances():
    ec2 = boto3.client('ec2',
                       aws_access_key_id=aws_access_key_id,
                       aws_secret_access_key=aws_secret_access_key,
                       region_name=region)

    instances = ec2.describe_instances()
    instance_details = []
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_details.append(instance['InstanceId'])

    instance_count = len(instance_details)
    instance_ids = "\n".join(instance_details)

    return f"Total number of instances: {instance_count}\nInstance IDs:\n{instance_ids}"

## Internal Audit on Instance using Shell Script
def internal_audit_report(instance_id, username='ec2-user'):
    instance_ip = get_ec2_instance_ip(instance_id)
    if not instance_ip:
        raise Exception(f"Could not find the instance {instance_id} in the region {region}.")

    ssh = SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(instance_ip, username=username, key_filename=PEM_FILE_PATH)

    # Commands to generate Audit report
    commands = [
        'sudo rm -rvf /tmp/linux_admin',
        'sudo rm -rvf /var/www/html/security_audit.html',
        'sudo yum update -y',
        'sudo yum install httpd git -y',
        'sudo systemctl start httpd',
		'sudo git clone https://github.com/Bhaskar-Soni/linux_admin.git /tmp/linux_admin >/dev/null 2>&1',
		'sudo bash /tmp/linux_admin/shell_scripts/linux_audit_with_html_report.sh >/dev/null 2>&1',
		'sudo mv /home/ec2-user/security_audit.html /var/www/html/',
		'sudo chown -R apache:apache /var/www/html/security_audit.html',
        'sudo chmod -R 755 /var/www/html/security_audit.html',
    ]

    for command in commands:
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode('utf-8').strip()
        error = stderr.read().decode('utf-8').strip()
        if error:
            raise Exception(f"Error running command '{command}': {error}")

    ssh.close()

    audit_report = f"http://{instance_ip}/security_audit.html"
    return (f"Internal Audit Run Successfully on **{instance_id}**\n"
            f"You can access the report at: {audit_report}\n")

# Function to run a command on EC2 instance using SSH
def run_command_on_instance(instance_id, command):
    try:
        # Retrieve the instance public DNS or IP address
        ec2 = boto3.client('ec2', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, region_name=region)
        response = ec2.describe_instances(InstanceIds=[instance_id])
        public_dns = response['Reservations'][0]['Instances'][0]['PublicDnsName']
        
        # Initialize SSH client
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())
        key = RSAKey(filename=PEM_FILE_PATH)
        
        # Connect to the instance
        ssh.connect(public_dns, username='ec2-user', pkey=key)
        
        # Run the command
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        
        ssh.close()
        
        if error:
            return f"Error: {error}"
        return output
    except Exception as e:
        return f"Error: {e}"