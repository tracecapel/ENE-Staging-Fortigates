from flask import Flask, render_template, request
import paramiko
import netmiko
from netmiko.fortinet import FortinetSSH
from netmiko import ConnectHandler
from werkzeug.utils import secure_filename
import re
import os
import time
import fortigate_api
from dotenv import load_dotenv




save_dir = os.path.join("C:/Users/tracecapel/Downloads/Staged")


#WHAT IS THIS DOING????????


# This script just does some of what you would normally do when staging (pasting base config in mobax... logging out... pasting more)
# There is no change to the staging process. Same flow, same base configs, the only difference is instead of using MobaX as our SSH client, we use netmiko and paramiko
# The flow is still -> SSH into pulbic ip -> drop field tech -> log out -> msod -> download backup, its just done automatically
# All this is doing is following the exact same staging process but using a standard python ssh client instead of moba.
#

# Check base config upload extension, must be a text file
ALLOWED_EXTENSIONS = {"txt"}

load_dotenv()

ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
MSOD_USERNAME = os.getenv('MSOD_USERNAME')
MSOD_PASSWORD = os.getenv('MSOD_PASSWORD')






# Runs a command, will busy wait until the hostname is sent back (indicating ready for next command)


#IMPORTANT: RECV consumes output of the terminal and will block if no more bytes to read.
# This function does not simply "read" the data - it will remove it from the buffer. This means
# receiving data or using RECV will block if the channel is cleared by it. For example, if my terminal output is: {  Fortigate-40F# get system status } and I
# call recv(4096) consuming all the output, the connection will block until more output is genereated - this is why we must use
# a lightweight command to "ping" (like system time) so we can remove the block and continue reading data
def run_command(command, shell, hostname, log):




    # Send the command to the shell
    shell.send(command + "\n")




    # Capture the shell output- this will be what the shell reads back after the command is executed, ie "FortiGate-40F #"
    output = ""
    last_data_time = time.time()
    deadline = time.time() + 300


    while time.time() < deadline:




        # If we dont see the hostname in the output, this means the shell is not ready for another command- busy wait
        if hostname.upper().strip("-") in output.upper():


            #Ok, we see the hostname (we are ready for another command)
            break


        #Make sure the shell is ready and dump/consume buffer and put into the output - if not, wait
        if shell.recv_ready():
            data = shell.recv(4096).decode("utf-8", errors="replace")
            output += data
            last_data_time = time.time()
        else:
            time.sleep(0.1)




    # Log the output in a buffer. Run a lightweight command to "ping" the console, if it returns the hostname, we know we are ready to send next command.
    # Because the configs are dropped in bulk, this really should never run unless commands are dropped line by line,
    # but could be helpful if we want to debug/diagnose things down the line
    if hostname.upper().strip("-") not in output.upper():




        buffer = ""
        while (
            hostname.upper().strip("-") not in buffer.upper()
            and time.time() < deadline
        ):
            shell.send("show system time\n")


            ping_deadline = time.time() + 10


            while time.time() < ping_deadline:
                if shell.recv_ready():
                    data = shell.recv(4096).decode("utf-8", errors="replace")
                    buffer += data
                    break


                time.sleep(0.1)


            time.sleep(0.1)




   


    return output








app = Flask(__name__)








@app.route("/")
def home():
    return render_template("index.html")






#When the user clicks "submit" all this code runs
@app.route("/submit", methods=["POST"])
def submit():
    if request.method == "POST":




        # Capture user input from the webpage
        eng = str(request.form.get("eng_number", "")).strip()
        ip = str(request.form.get("ip", "")).strip()




        # Sanity checks for ENG and ip input - DONT LET THE USER UPLOAD WRONG ENG/INVALID IP, OR ANY MALICIOUS FILES
        # Ex. 70.116.215.56 / ENG-12345678




        # Regex to check the IP's and the ENG number
        ip_regex = (
            r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
            r"(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}"
        )
        eng_regex = r"ENG-[0-9]{8}"




        # If they match, init a new SSH client
        if re.fullmatch(ip_regex, ip) and re.fullmatch(eng_regex, eng):




            if not ADMIN_PASSWORD or not MSOD_PASSWORD:
                return "FortiGate credentials are not configured"


            #Paramiko client- this is like an invisible MobaX or another SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())


            #Attempt to connect- with admin and mandolorian (like you do normally during staging)
            try:




                ssh.connect(
                    hostname=ip,
                    username=ADMIN_USERNAME,
                    password=ADMIN_PASSWORD,
                    timeout=15,
                    banner_timeout=15,
                    auth_timeout=15
                )
            except Exception as exc:
                print("Connection failed:", exc)
                ssh.close()
                return "Connection failed"


            #'test' the connection, if we can use get sys status, we are good.
            try:
                stdin, stdout, stderr = ssh.exec_command(
                    "get system status",
                    timeout=30
                )




                # Capture the serial number
                serial = ""
                status_output = stdout.read().decode("utf-8", errors="replace")


                for line in status_output.splitlines():
                    if "Serial-Number" in line:
                        serial = line.split(":", 1)[1].strip()
                        break




                #Connection established, terminal produced output
                if status_output:




                    #Process the base config file uploaded by user + extension sanity checks
                    try:
                        file = request.files.get("base_config")


                        if file is None or not file.filename:
                            return "Invalid File"


                        filename = secure_filename(file.filename)


                        if (
                            not filename
                            or "." not in filename
                            or filename.rsplit(".", 1)[1].lower()
                            not in ALLOWED_EXTENSIONS
                        ):
                            return "Invalid File"
                    except Exception:
                        return "Invalid File"




                    byte_stream = file.stream




                    text = ""
                    for byte in byte_stream:
                        if isinstance(byte, bytes):
                            text += byte.decode("utf-8", errors="replace")
                        else:
                            text += str(byte)




                    shell = ssh.invoke_shell()
                    shell.settimeout(10)




                    #Maybe find a more robust way to do this- but this is what "splits" the base config between FT/Config and uses admin/MSOD respectively
                    split_marker = (
                        "#!=========== ABOVE THIS LINE IS FOR THE FIELD TECH "
                        "TO PROVIDE REMOTE ACCESS! ====="
                    )


                    split = text.split(split_marker, 1)


                    if len(split) != 2:
                        return "Invalid base config format"


                    #Capture hostname to validate commands (if we see hostname # = good)
                    hostname_match = re.search(
                        r"(?m)^\s*set\s+hostname\s+(.+?)\s*$",
                        text
                    )


                    if not hostname_match:
                        return "Hostname not found in base config"


                    hostname = hostname_match.group(1).strip()


                    #Remove hostname sepcial chars (if any??)
                    hostname = re.sub(
                        r"[^A-Za-z0-9_.-]",
                        "",
                        hostname
                    )


                    if not hostname:
                        return "Invalid hostname"


                    eng_dir = os.path.join(save_dir, eng)
                    os.makedirs(eng_dir, exist_ok=True)


                    #All final stagings follow this name syntax. Save it to our ENG# dir
                    log = open(os.path.join(
                        eng_dir,
                        str(hostname) + "_7-4_2878_STAGING_FINAL.conf"),
                        "w",
                        encoding="utf-8"
                    )




                    try:




                        field_tech_script = split[0]




                        ft_conact = ""
                        ft_conact += "diagnose debug config-error-log clear\n"




                        for command in field_tech_script.splitlines():
                            command = command.strip()


                            if command:
                                ft_conact += str(command + "\n")








                        #Change hostname, register in forticloud, update, clear debug config log etc etc... very efficiently written


                       
                        ft_conact += "config system global\n"
                        ft_conact += "set hostname " + hostname + "\n"
                        ft_conact += "end\n"




                        ft_conact += "config system fortiguard\n"
                        ft_conact += "set update-server-location usa\n"
                        ft_conact += "end\n"


                        ft_conact += (
                            'exe fortiguard-log login DL-SEE&O-ENEService@charter.com "&nxjMFBmjiBcTb.%ZJ7r" US DL-SEE&O-ENEService@charter.com\n'
                        )


                        ft_conact += "exe update-now\n"






                        ft_conact += "edit MSOD_Admin\n"
                        ft_conact += "set password " + MSOD_PASSWORD + "\n"
                        ft_conact += "next\n"
                        ft_conact += "end\n"


                        #This is where we drop the FT script
                        run_command(ft_conact, shell, hostname, log)




                        base_config = split[1]


                        #Close connection - DO NOT proceed until we successfully close the SSH connection
                        while(True):




                            try:




                                ssh.close()
                                break
                            except Exception:
                                print("Closed failed... retrying")
                                time.sleep(1)






                        #Reconnect now, but this time with MSOD credentials for the actual config part
                        while(True):
                            time.sleep(1)


                            try:
                                ssh.connect(
                                    hostname=ip,
                                    username=MSOD_USERNAME,
                                    password=MSOD_PASSWORD,
                                    timeout=15,
                                    banner_timeout=15,
                                    auth_timeout=15
                                )


                                stdin, stdout, stderr = ssh.exec_command(
                                    "get system status",
                                    timeout=30
                                )


                                status_output = stdout.read().decode(
                                    "utf-8",
                                    errors="replace"
                                )


                                if status_output:
                                    break


                            except Exception:


                                print("Connection failed, retrying")






                        #Get the shell
                        shell = ssh.invoke_shell()
                        shell.settimeout(10)






                        #Read from base config, starting from where we split it earlier (this is just (full base config - field tech))
                        config_concat = ""
                        for command in base_config.splitlines():
                            command = command.strip()


                            if command:
                                config_concat += str(command + "\n")




                        run_command(config_concat, shell, hostname, log)








                        #Capture any errors from base config
                        stdin, stdout, stderr = ssh.exec_command(
                            "diagnose debug config-error-log read",
                            timeout=30
                        )


                        error_output = stdout.read().decode(
                            "utf-8",
                            errors="replace"
                        )




                        with open(
                            os.path.join(eng_dir, hostname + "_error_log.txt"),
                            "w",
                            encoding="utf-8"
                        ) as err:
                            for line in error_output.splitlines():
                                err.write(line + "\n")








                       
                       
                        #Close connection
                        ssh.close()


                        #Here we login via netmiko, mainly because it doesent paginate the output from show-full-cofig
                        try:
                            fortigate = {
                            'device_type' : 'fortinet',
                            'host' : ip,
                            'username' : MSOD_USERNAME,
                            'password' : MSOD_PASSWORD,
                            'port' : 22,
                            }

                            

                            with ConnectHandler(**fortigate) as netconnect:
                                backup_config = netconnect._send_command_str("show full-configuration")
                                
                               

                                
                                for line in backup_config.splitlines():
                                    log.write(line + "\n")
                                print(backup_config)
                        except Exception as e:
                            print("Backup download failed:" + e)




                        return "https://" + str(ip) + " " + str(serial) #+ str(MSOD_PASSWORD)


                    finally:
                        try:
                            log.close()
                        except Exception:
                            pass




                else:
                    ssh.close()
                    return "Couldnt reach Fortigate. IP, credentials, or connection failed"


            except Exception as exc:
                print("Processing failed:", exc)


                try:
                    ssh.close()
                except Exception:
                    pass


                return "FortiGate processing failed"




        else:




            return "Invalid IP or ENG!"








if __name__ == "__main__":
    app.run(debug=True)
