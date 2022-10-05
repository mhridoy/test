import streamlit as st



import nmap

#scanner = ""
#scanner = nmap.PortScanner()

ip_addr = st.text_input("Please enter the IP address you want to scan: ")


if(st.button("Submit")):
    st.write("The IP you entered is: ", ip_addr)


#type(ip_addr)

resp = st.text_input("""\nPlease enter the type of scan you want to run
                1)SYN ACK Scan
                2)UDP Scan
                3)Comprehensive Scan \n""")
st.write("You have selected option: ", resp)
resp_dict={'1':['-v -sS','tcp'],'2':['-v -sU','udp'],'3':['-v -sS -sV -sC -A -O','tcp']}
if resp not in resp_dict.keys():
    st.write("enter a valid option")
else:
    st.write("nmap version: ",scanner.nmap_version())
    scanner.scan(ip_addr,"1-1024",resp_dict[resp][0])
    st.write(scanner.scaninfo())
    if scanner.scaninfo()=='up':
        st.write("Scanner Status: ",scanner[ip_addr].state())
        st.write(scanner[ip_addr].all_protocols())
        st.write("Open Ports: ",scanner[ip_addr][resp_dict[resp][1]].keys())
