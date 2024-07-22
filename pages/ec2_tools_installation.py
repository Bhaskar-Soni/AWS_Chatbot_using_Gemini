import boto3
import paramiko
import time
from paramiko import SSHClient, AutoAddPolicy, RSAKey
from cryptography.fernet import Fernet
from config import CREDENTIALS_FILE, ENCRYPTION_KEY_FILE, PEM_FILE_PATH

# Load encryption key
def load_key():
    with open(ENCRYPTION_KEY_FILE, 'rb') as f:
        return f.read()

# Initialize Fernet cipher suite with loaded encryption key
key = load_key()
cipher_suite = Fernet(key)

# Decrypt data function
def decrypt_data(encrypted_data):
    decrypted_data = cipher_suite.decrypt(encrypted_data.encode())
    return decrypted_data.decode()

# Load credentials from file and decrypt them
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

# Function to check if Apache is Installed or not
def check_apache_status(instance_ip, username='ec2-user'):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(instance_ip, username=username, key_filename=PEM_FILE_PATH)

    try:
        # Check if Apache service is active
        stdin, stdout, stderr = ssh.exec_command('sudo systemctl is-active httpd')
        service_status = stdout.read().decode('utf-8').strip()
        if service_status != 'active':
            return False

        # Check if Apache is installed
        stdin, stdout, stderr = ssh.exec_command('httpd -v')
        apache_version = stdout.read().decode('utf-8').strip()
        if 'Server version' not in apache_version:
            return False
    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        ssh.close()
        
    return True

# Function to install Apache on an EC2 instance
def install_apache(instance_id, username='ec2-user'):
    instance_ip = get_ec2_instance_ip(instance_id)
    if not instance_ip:
        raise Exception(f"Could not find the instance {instance_id} in the region {region}.")

    ssh = SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(instance_ip, username=username, key_filename=PEM_FILE_PATH)

    # Check if MySQL is already installed and running
    if check_apache_status(instance_ip, username):
        ssh.close()
        return (f"Apache services are running and Apache is already installed.\n"
            f"You can check using this URL: http://{instance_ip}\n")

    # Commands to install Apache
    commands = [
        'sudo yum update -y',
        'sudo yum install httpd -y',
        'sudo systemctl start httpd',
    ]

    for command in commands:
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode('utf-8').strip()
        error = stderr.read().decode('utf-8').strip()
        if error:
            raise Exception(f"Error running command '{command}': {error}")

    ssh.close()

    return (f"Apache installed successfully on instance {instance_id}\n"
        f"You can check using this URL: http://{instance_ip}\n")

# Function to check if MySQL is Installed or not
def check_mysql_status(instance_ip, username='ec2-user'):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(instance_ip, username=username, key_filename=PEM_FILE_PATH)

    try:
        # Check if MySQL service is active
        stdin, stdout, stderr = ssh.exec_command('sudo systemctl is-active mysqld')
        service_status = stdout.read().decode('utf-8').strip()
        if service_status != 'active':
            return False

        # Check if MySQL is installed
        stdin, stdout, stderr = ssh.exec_command('mysql --version')
        mysql_version = stdout.read().decode('utf-8').strip()
        if 'Ver' not in mysql_version:
            return False
    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        ssh.close()

    return True

# Function to install MYSQL 
def install_mysql(instance_id, username='ec2-user'):
    instance_ip = get_ec2_instance_ip(instance_id)
    if not instance_ip:
        raise Exception(f"Could not find the instance {instance_id} in the region.")

    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(instance_ip, username=username, key_filename=PEM_FILE_PATH)

    # Check if MySQL is already installed and running
    if check_mysql_status(instance_ip, username):
        ssh.close()
        return "MySQL services are running and MySQL is already installed."

    # Commands to install MySQL/MariaDB
    install_commands = [
        "sudo yum clean all --verbose",
        "sudo yum update -y",
        "sudo yum install expect -y",
        "sudo rm -rvf /tmp/mysql*",
        "sudo wget -q https://dev.mysql.com/get/mysql57-community-release-el7-9.noarch.rpm -P /tmp/",
        "sudo rpm --import https://repo.mysql.com/RPM-GKEY-mysql >/dev/null 2>&1",
        "sudo rpm -ivh --force /tmp/mysql57-community-release-el7-9.noarch.rpm >/dev/null 2>&1",
        "sudo yum update -y >/dev/null 2>&1",
        "sudo yum install mysql-server -y --skip-broken --nogpgcheck",
        "sudo systemctl start mysqld"
    ]

    for command in install_commands:
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode('utf-8').strip()
        error = stderr.read().decode('utf-8').strip()
        if error:
            raise Exception(f"Error running command '{command}': {error}")

    # Wait a moment for MySQL to start and generate the temporary password
    time.sleep(10)

    # Retrieve the temporary password
    stdin, stdout, stderr = ssh.exec_command("sudo grep 'temporary password' /var/log/mysqld.log | awk '{print $NF}'")
    temp_password = stdout.read().decode('utf-8').strip()
    error = stderr.read().decode('utf-8').strip()
    if error:
        raise Exception(f"Error retrieving temporary password: {error}")

    # Secure installation script with a stronger password using expect
    new_root_password = 'NewP@ssw0rd123!'

    secure_install_script = f"""#!/usr/bin/expect

spawn sudo mysql_secure_installation
expect "Enter password for user root:"
send "{temp_password}\r"
expect "New password:"
send "{new_root_password}\r"
expect "Re-enter new password:"
send "{new_root_password}\r"
expect "Change the password for root ? ((Press y|Y for Yes, any other key for No) :"
send "n\r"
expect "Remove anonymous users? (Press y|Y for Yes, any other key for No) :"
send "y\r"
expect "Disallow root login remotely? (Press y|Y for Yes, any other key for No) :"
send "y\r"
expect "Remove test database and access to it? (Press y|Y for Yes, any other key for No) :"
send "y\r"
expect "Reload privilege tables now? (Press y|Y for Yes, any other key for No) :"
send "y\r"
expect eof
"""

    script_filename = "/tmp/secure_install_mysql.sh"
    with open(script_filename, 'w') as script_file:
        script_file.write(secure_install_script)

    ftp = ssh.open_sftp()
    ftp.put(script_filename, script_filename)
    ftp.close()

    stdin, stdout, stderr = ssh.exec_command(f"chmod +x {script_filename}; expect {script_filename}")
    output = stdout.read().decode('utf-8').strip()
    error = stderr.read().decode('utf-8').strip()
    if error:
        raise Exception(f"Error running secure installation script: {error}")

    ssh.close()

    return (f"MySQL installed and configured successfully.\n"
            f"Root Password: {new_root_password}\n")

# Function to check if PHP is Installed or not
def check_php_status(instance_ip, username='ec2-user'):
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    try:
        ssh.connect(instance_ip, username=username, key_filename=PEM_FILE_PATH)
        stdin, stdout, stderr = ssh.exec_command('php -v')
        php_version = stdout.read().decode('utf-8').strip()
        return 'PHP' in php_version
    except Exception as e:
        print(f"Error: {e}")
        return False
    finally:
        ssh.close()

## Function to Install PHP on Instance
def install_php_and_configure(instance_id, username='ec2-user'):
    instance_ip = get_ec2_instance_ip(instance_id)
    if not instance_ip:
        raise Exception(f"Could not find the instance {instance_id} in the region {region}.")

    ssh = SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(instance_ip, username=username, key_filename=PEM_FILE_PATH)

    # Check if MySQL is already installed and running
    if check_php_status(instance_ip, username):
        ssh.close()
        return f"PHP services are running and PHP is already installed.\n"

    # Commands to install Apache
    commands = [
        'sudo yum install httpd php php-pdo php-mysqlnd php-cli php-fpm php-gd git -y',
        'sudo systemctl restart httpd',
        "sudo sed -i 's/;\\s*allow_url_fopen =.*/allow_url_fopen = On/' /etc/php.ini",
        "sudo sed -i 's/;\\s*allow_url_include =.*/allow_url_include = On/' /etc/php.ini",
        "sudo sed -i 's/;\\s*display_errors =.*/display_errors = Off/' /etc/php.ini"
    ]

    for command in commands:
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode('utf-8').strip()
        error = stderr.read().decode('utf-8').strip()
        if error:
            raise Exception(f"Error running command '{command}': {error}")

    ssh.close()

    return f"PHP installed successfully on instance {instance_id}\n"

# Function to install WordPress on an EC2 instance
def install_wordpress(instance_id, username='ec2-user'):
    instance_ip = get_ec2_instance_ip(instance_id)
    if not instance_ip:
        raise Exception(f"Could not find the instance {instance_id} in the region.")

    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(instance_ip, username=username, key_filename=PEM_FILE_PATH)

    # Check if Apache is already installed and running
    if not check_apache_status(instance_ip, username):
        ssh.close()
        return "Apache is not installed or not running. You can use **Install Apache** command to install it!"

    # Check if MySQL is already installed and running
    if not check_mysql_status(instance_ip, username):
        ssh.close()
        return "MySQL is not installed or not running. You can use **Install MySQL** command to install it."

    # Create MySQL database and user for WordPress
    db_name = "wordpress"
    db_user = "wordpressuser"
    db_pass = "W0rDPrE$$#123!"
    new_root_password = 'NewP@ssw0rd123!'

    # Create .my.cnf file with MySQL credentials
    my_cnf = f"""
[client]
user=root
password={new_root_password}
"""
    sftp = ssh.open_sftp()
    with sftp.file('/home/ec2-user/.my.cnf', 'w') as file:
        file.write(my_cnf)
    sftp.chmod('/home/ec2-user/.my.cnf', 0o600)
    sftp.close()

    mysql_commands = [
        f"mysql -e 'CREATE DATABASE {db_name};'",
        f"mysql -e 'CREATE USER {db_user}@localhost IDENTIFIED BY \"{db_pass}\";'",
        f"mysql -e 'GRANT ALL PRIVILEGES ON {db_name}.* TO {db_user}@localhost;'",
        f"mysql -e 'FLUSH PRIVILEGES;'"
    ]

    for command in mysql_commands:
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode('utf-8').strip()
        error = stderr.read().decode('utf-8').strip()
        if error:
            raise Exception(f"Error running MySQL command '{command}': {error}")

    # Remove .my.cnf file after use
    ssh.exec_command('rm /home/ec2-user/.my.cnf')

    # Commands to install WordPress
    wordpress_commands = [
        "sudo yum update -y",
        "sudo yum install -y php php-mysqli php-fpm php-gd --skip-broken",
        "sudo wget -q https://wordpress.org/latest.tar.gz -P /tmp/",
        "sudo tar -zxvf /tmp/latest.tar.gz -C /var/www/html/",
        "sudo chown -R apache:apache /var/www/html/wordpress",
        "sudo chmod -R 755 /var/www/html/wordpress",
        "sudo cp /var/www/html/wordpress/wp-config-sample.php /var/www/html/wordpress/wp-config.php",
        f"sudo sed -i 's/database_name_here/{db_name}/g' /var/www/html/wordpress/wp-config.php",
        f"sudo sed -i 's/username_here/{db_user}/g' /var/www/html/wordpress/wp-config.php",
        f"sudo sed -i 's/password_here/{db_pass}/g' /var/www/html/wordpress/wp-config.php",
        "sudo sed -i '/AUTH_KEY/d' /var/www/html/wordpress/wp-config.php",
        "sudo sed -i '/SECURE_AUTH_KEY/d' /var/www/html/wordpress/wp-config.php",
        "sudo sed -i '/LOGGED_IN_KEY/d' /var/www/html/wordpress/wp-config.php",
        "sudo sed -i '/NONCE_KEY/d' /var/www/html/wordpress/wp-config.php",
        "sudo sed -i '/AUTH_SALT/d' /var/www/html/wordpress/wp-config.php",
        "sudo sed -i '/SECURE_AUTH_SALT/d' /var/www/html/wordpress/wp-config.php",
        "sudo sed -i '/LOGGED_IN_SALT/d' /var/www/html/wordpress/wp-config.php",
        "sudo sed -i '/NONCE_SALT/d' /var/www/html/wordpress/wp-config.php",
        "curl -s https://api.wordpress.org/secret-key/1.1/salt/ > /tmp/wp-keys.txt",
        "sudo sed -i '/@-/r /tmp/wp-keys.txt' /var/www/html/wordpress/wp-config.php",
        "sudo rm /tmp/wp-keys.txt",
        "sudo sed -i 's/AllowOverride None/AllowOverride All/' /etc/httpd/conf/httpd.conf",
        "sudo systemctl restart httpd",
        "sudo touch /var/www/html/.htaccess",
        "sudo chmod 644 /var/www/html/.htaccess",
        "sudo sed -i '/LoadModule rewrite_module/s/^#//g' /etc/httpd/conf/httpd.conf",
        "sudo systemctl restart httpd"
    ]

    for command in wordpress_commands:
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode('utf-8').strip()
        error = stderr.read().decode('utf-8').strip()
        if error:
            raise Exception(f"Error running command '{command}': {error}")

    ssh.close()

    wordpress_url = f"http://{instance_ip}/wordpress/"
    return f"WordPress installed successfully on instance {instance_id}. URL: {wordpress_url}"

# Function to install DVWA on an EC2 instance
def install_dvwa(instance_id, username='ec2-user'):
    instance_ip = get_ec2_instance_ip(instance_id)
    if not instance_ip:
        raise Exception(f"Could not find the instance {instance_id} in the region.")

    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(instance_ip, username=username, key_filename=PEM_FILE_PATH)

    # Check if Apache is already installed and running
    if not check_apache_status(instance_ip, username):
        ssh.close()
        return "Apache is not installed or not running. You can use **Install Apache** command to install it!"

    # Check if MySQL is already installed and running
    if not check_mysql_status(instance_ip, username):
        ssh.close()
        return "MySQL is not installed or not running. You can use **Install MySQL** command to install it."
		
	# Check if PHP is already installed and running
    if not check_php_status(instance_ip, username):
        ssh.close()
        return "PHP is not installed or not running. You can use **Install PHP** command to install it."

    # Create MySQL database and user for WordPress
    db_name = "dvwa"
    db_user = "dvwa"
    db_pass = "DvW@$#123!"
    new_root_password = 'NewP@ssw0rd123!'

    # Create .my.cnf file with MySQL credentials
    my_cnf = f"""
[client]
user=root
password={new_root_password}
"""
    sftp = ssh.open_sftp()
    with sftp.file('/home/ec2-user/.my.cnf', 'w') as file:
        file.write(my_cnf)
    sftp.chmod('/home/ec2-user/.my.cnf', 0o600)
    sftp.close()

    mysql_commands = [
        f"mysql -e 'CREATE DATABASE {db_name};'",
        f"mysql -e 'CREATE USER {db_user}@localhost IDENTIFIED BY \"{db_pass}\";'",
        f"mysql -e 'GRANT ALL PRIVILEGES ON {db_name}.* TO {db_user}@localhost;'",
        f"mysql -e 'FLUSH PRIVILEGES;'"
    ]

    for command in mysql_commands:
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode('utf-8').strip()
        error = stderr.read().decode('utf-8').strip()
        if error:
            raise Exception(f"Error running MySQL command '{command}': {error}")

    # Remove .my.cnf file after use
    ssh.exec_command('rm /home/ec2-user/.my.cnf')

    # Commands to install DVWA
    dvwa_commands = [
		'sudo git clone https://github.com/digininja/DVWA.git /tmp/DVWA >/dev/null 2>&1',
		'sudo mv /tmp/DVWA /var/www/html/',
		'sudo cp /var/www/html/DVWA/config/config.inc.php.dist /var/www/html/DVWA/config/config.inc.php',
		f"sudo sed -i 's/p@ssw0rd/{db_pass}/g' /var/www/html/DVWA/config/config.inc.php",		
		'sudo chown -R apache:apache /var/www/html/DVWA',
		'sudo chmod -R 755 /var/www/html/DVWA',
		'sudo systemctl restart mysqld',
        'sudo systemctl restart httpd'
    ]

    for command in dvwa_commands:
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode('utf-8').strip()
        error = stderr.read().decode('utf-8').strip()
        if error:
            raise Exception(f"Error running command '{command}': {error}")

    ssh.close()

    dvwa_url = f"http://{instance_ip}/DVWA/"
    return f"DVWA installed successfully on instance **{instance_id}** with default username: **admin**, password: **password**. **URL:** {dvwa_url}"