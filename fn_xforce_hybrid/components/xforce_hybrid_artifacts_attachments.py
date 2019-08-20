# -*- coding: utf-8 -*-
# pragma pylint: disable=unused-argument, no-self-use
"""
###########################################################
#  Xforce , hybrid analysis api integration with resilient#
#  Author: Ahmed Amin                                     #
#  security engineer and software developer               #
###########################################################
"""

"""Function implementation"""

import logging
import requests
from requests import session
import resilient
import optparse
from base64 import b64encode
import tempfile
import hashlib
import re
import os
from resilient_circuits import ResilientComponent, function, handler, StatusMessage, FunctionResult, FunctionError


class FunctionComponent(ResilientComponent):
    """Component that implements Resilient function 'xforce_hybrid_artifacts_attachments"""

    def __init__(self, opts):
        """constructor provides access to the configuration options"""
        super(FunctionComponent, self).__init__(opts)
        self.options = opts.get("fn_xforce_hybrid", {})

    @handler("reload")
    def _reload(self, event, opts):
        """Configuration options have changed, save new values"""
        self.options = opts.get("fn_xforce_hybrid", {})

    @function("xforce_hybrid_artifacts_attachments")
    def _xforce_hybrid_artifacts_attachments_function(self, event, *args, **kwargs):
        """Function: function for analyze attachments and artifacts contain files or ips"""
        
        TEMP_FILES = []

        #check workflow status if it terminate
        def get_workflow_status(workflow_instance_id , res_client):
            """Function to get the status of the current workflow"""
            res = res_client.get("/workflow_instances/{0}".format(workflow_instance_id))
            return res['status']
        
        #check required values for function inputs
        def get_config_option(option_name , optional = False):
            """Function to check if a given option is in app.config"""
            option = self.options.get(option_name)

            if option is None and optional is False:
                error = "'{0}' is mandatory and is not set in ~/.resilient/app.config file . you must set it value".format(option)
                raise ValueError(error)       
            else:
                return option    

        #remove tmp files after finishing the operation
        def remove_tmp_files(files):
            """Function for remove temp files"""       
            for tmp_file in files:
                os.remove(tmp_file)


        def get_input_workflow(client , incident_id , attachment_id , artifact_id):
            """ function to get workflow inputs and start to init the request"""
            #add validation schema for entered ip
            """
            supported ip format 1.2.3.5 , 183.254.152.128 , 22,24,35,89
            """
            re_ip_match_pattern = r"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}$"
            #prepare the request body
            body = {"incident_id": incident_id , "id": None , "type": "" , "meta_data": None , "data": None , "ip":None}

            if (attachment_id):
                body["type"] = "attachment"
                body["id"] = attachment_id 
                body["meta_data"] = client.get("/incidents/{0}/attachments/{1}".format(body['incident_id'],body['id']))       
                body["data"] = client.get_content("/incidents/{0}/attachments/{1}/contents".format(body['incident_id'] , body['id']))
            
            elif (artifact_id):
                body["type"] = "artifact"
                body["id"] = artifact_id
                body["meta_data"] = client.get("/incidents/{0}/artifacts/{1}".format(body["incident_id"] , body["id"]))
                #parse artifact to identify if artifact is ip address or attachment
                if (body["meta_data"]["attachment"]):
                    body["data"] = client.get_content("/incidents/{0}/artifacts/{1}/contents".format(body["incident_id"] , body["id"]))
                else:
                    valid = re.match(re_ip_match_pattern , body["meta_data"]["value"] )
                    if (valid):
                        body["ip"] = valid.group()
                    else:
                        sample_format = "1.2.3.5"
                        raise ValueError("Enter a valid format ip like this {}".format(sample_format))  
            
            return body    

        def generate_header(api_key , api_password):
            """Function to generate header for Xforce API"""
            header = api_key + ":" + api_password
            return b64encode(header.encode('utf-8')) 

        def calculate_file_hash(path):
            """Function for calculation file hash"""
            hasher = hashlib.sha256()
            try:
                with open(path,'r+b') as file:
                    buffer = file.read()
                    hasher.update(buffer)
                    file.close()
                    return hasher.hexdigest()
            except IOError as error:
                print("an error occured or %s" , error)

                

        def write_temp_file(data , name=None):
            """Function for writing tempdir and writing binary"""
            path = None
            
            if (name):
                path = "{0}/{1}".format(tempfile.gettempdir(),name)
            
            else:
                tf = tempfile.mkstemp(suffix = "test", prefix="suspect_attachment")
                dis, path = tf

            try:
                #path:  /tmp/attachment_name   
                build_file = open(path,'wb')
                TEMP_FILES.append(path)
                build_file.write(data)
                build_file.close()
            
            except IOError as error:
                print("something wrong or %s" , error)    
            return path

        def check_response(response , body):
            """Function for checking response status"""
            if body["type"] == "attachment":
                malicious = None
                if response.status_code == 200:
                    print("hash has been submited succssefully")
                    malicious = True
                elif response.status_code == 404:
                    malicious = False
                else:
                    print("status_code : {0}".format(response.status_code) , response.json()['error']) 
                return malicious    
            
            elif body["ip"]:
                return True if len(response.json()["malware"]) > 0 else False
            
            elif body["type"] == "artifact":
                print("init scanning artifact...")
                for item in response.json():
                    if item == "scanners":
                        for element in response.json()[item]:
                            return True if element["status"] == "malicious" else False
        
        def process_response(response , body):
            """ function for extracting important info about the submited hash"""
            if body["type"] == "attachment":
                attachment_info_status = dict()
                if check_response(response , body):
                    res_json = response.json()
                    print("trying to extract brif info about the hash result ......")
                    attachment_info_status['status'] = "malware"
                    attachment_info_status['malicious'] = True
                    for key , value in res_json["malware"].items():
                        if key == "origins":
                            for nested_key in res_json["malware"][key]:
                                attachment_info_status["family"] = res_json['malware'][key][nested_key]['family'][0]
                        elif key == "risk":
                            attachment_info_status["risk"] = value
                    print("Result obtained successfully.....")        
                    return attachment_info_status
                else:
                    print("Hash is Not regconized as malicious hash.....")        
                    return {'status':'clean_attachment' , "malicious": False}
            elif body["ip"]:
                ip_info_status = {
                                "label": "ip",
                                "type": "",
                                "malware_info":[],
                                "family": ""
                                }
                if check_response(response , body):
                    res_json = response.json()
                    print("trying to extract brif info about the ip reputation")
                    #limit the result to 3
                    prifix = [x for x in range(3)]
                    ip_info_status["type"] = res_json['malware'][0]['type']
                    ip_info_status['malicious'] = True
                    ip_info_status['status'] = "InfectedIP"
                    for key in prifix:
                        ip_info_status["malware_info"].append({'domain_name':res_json['malware'][key]['domain'] 
                        , 'file_path': res_json['malware'][key]['filepath'] , 
                        'lastseen': res_json['malware'][key]['lastseen']})
                    
                    ip_info_status['family'] = res_json['malware'][0]['family'][0]
                    print("Result obtained successfully.....")        
                    return ip_info_status
                else:    
                    print("the given ip is clear and not infected by malware")
                    return {"status":"clean_ip" , "malicious": False , "label":"ip"}
            
            elif body["type"] == "artifact":
                if check_response(response , body):
                    scanners = response.json()["scanners"]
                    artifact_info_status = {"scanners": [] , "label": "attachment_suspect"}
                    artifact_info_status["malicious"] = True
                    print("trying extract brif infomartion about the artifact")
                    for element in scanners:
                        artifact_info_status["scanners"].append({"name":element["name"]
                             , "status":element["status"] , "progress":element["progress"]})
                    print(artifact_info_status)
                    return artifact_info_status     
                else:
                    scanners = response.json()["scanners"]
                    artifact_info_status = {"scanners": [] , "label": "attachment_suspect"}
                    artifact_info_status["malicious"] = False
                    for element in scanners:
                        artifact_info_status["scanners"].append({"name":element["name"]
                        , "status":element["status"] , "progress":element["progress"]})
                    return artifact_info_status     


        def submit_hash_file(url_api , end_point , file_hash , header , body):
            """Function for submiting hash file """
            response = requests.get("{0}{1}{2}".format(url_api,end_point,file_hash) , headers = header , verify = False)
            if(response is not None):
                result = process_response(response,body)
                return result
            else:
                print("something going wrong could be missing header or expired api or connection failed")  

        def submit_artifact_attachment(url_api , end_point , attachment , header , data , body):
            """Function for scan artifact attachments via virustotal ..etc"""
            try:
                with open(attachment , "rb") as file:
                    response = requests.post("{0}{1}".format(url_api,end_point) , headers = header , data = data , files = {'file': file})
                    file.close()
                    if(response is not None):
                        result = process_response(response , body)
                        return result     
            except IOError as error:
                raise ValueError("{0}".format(error)) 
        
        def is_malicious(result):
            return True if result["malicious"]  else False

        def submit_ip(url_api , end_point , target_ip , header , body):
            """Function for submiting ip for quering reputation"""
            response = requests.get("{0}{1}{2}".format(url_api,end_point,target_ip) , headers = header , verify = False)
            if(response is not None):
                result = process_response(response,body)
                return result
            else:
                print("something going wrong could be missing header or expired api or connection failed")      

        try:
            # Get the wf_instance_id of the workflow this Function was called in
            wf_instance_id = event.message["workflow_instance"]["workflow_instance_id"]

            # Get Xforce options from config file
            XFORCE_API_URL = get_config_option("xforce_api")
            XFORCE_API_KEY = get_config_option("xforce_api_key")
            XFORCE_API_PASSWORD = get_config_option("xforce_api_password")
            XFORCE_API_KEY = get_config_option("xforce_api_key")
            XFORCE_MALWARE_ENDPOINT = get_config_option("xforce_malware_endpoint",optional=True)
            XFORCE_IP_ENDPOINT = get_config_option("xforce_ipReputation_endpoint",optional=True)
            HYBRID_API_URL = get_config_option("hybrid_api")
            HYBRID_SCAN_ENDPOINT = get_config_option("hybrid_scan_endpoint")
            HYBRID_API_KEY = get_config_option("hybrid_api_key")


            #prepare header XFORCE API
            header_X = {
                "Content-Type": "application/json",
                "Authorization": "Basic {0}".format(generate_header(XFORCE_API_KEY , XFORCE_API_PASSWORD).decode("utf-8"))
            }

            #prepare header HYBRID API

            header_H = {
             "api-key": HYBRID_API_KEY,
             "user-agent": "Falcon Sandbox"
            }

            #prepare data for HYBRID Api
            data = {
                "scan_type": "all"
            }


            # Get the function parameters:
            attachment_name = kwargs.get("attachment_name")  # text
            
            incident_id = kwargs.get("incident_id")  # number
            
            attachment_id = kwargs.get("attachment_id")  # number
            artifact_id = kwargs.get("artifact_id")  # number


            #check required inputs are defined
            if incident_id is None:
                raise ValueError("incident_id is required value...")

            if not attachment_id and not artifact_id:
                raise ValueError("attachment_id or artifact_id is required")


            #init resilient client
            parser = resilient.ArgumentParser(config_file=resilient.get_config_file())
            opts = parser.parse_args()
            client = resilient.get_client(opts)

            log = logging.getLogger(__name__)
            log.info("attachment_name: %s", attachment_name)
            log.info("incident_id: %s", incident_id)
            log.info("attachment_id: %s", attachment_id)
            log.info("artifact_id: %s", artifact_id)

            # PUT YOUR FUNCTION IMPLEMENTATION CODE HERE
            yield StatusMessage("starting.......")
            # Get Body we working on
            body = get_input_workflow(client, incident_id, attachment_id, artifact_id)


            workflow_status = get_workflow_status(wf_instance_id, client)

            file_hash = None
            query_ip  = None

            if (body["type"] == "attachment" and body["data"] != None):
                #temp file name should be /tmp/attachment_name 
                temp_file_path = write_temp_file(body["data"] , attachment_name)
                # calculate hash file
                yield StatusMessage("Trying calculating file hash.........")
                file_hash = calculate_file_hash(temp_file_path)
            
            elif (body["ip"]):
                query_ip  = body["ip"]

            elif (body["type"] == "artifact" and body["data"] != None):
                yield StatusMessage("Writing artifact attachment.........")
                temp_artifact_file_path = write_temp_file(body["data"])



            if (file_hash):
                print("starting submiting file hash.........")
                response = submit_hash_file(XFORCE_API_URL,XFORCE_MALWARE_ENDPOINT,file_hash,header_X,body)
                if (response):
                    print("getting the results successfully.........")
                    if is_malicious(response):
                        results = {
                        "status": response["status"],
                        "family": response["family"],
                        "risk": response["risk"],
                        "filename": attachment_name}
                    else:
                        results = {
                        "status": response["status"],
                        "filename": attachment_name}
                else:
                    yield StatusMessage("file hash not provied well..")   

            elif (query_ip):
                print("starting submiting ip.....")
                response = submit_ip(XFORCE_API_URL,XFORCE_IP_ENDPOINT,query_ip,header_X,body)
                if (response):
                    print("getting the results successfully.........")
                    if is_malicious(response):
                        results = {
                        "label": response["label"],
                        "type": response["type"],
                        "status": response["status"],
                        "malware_info":response["malware_info"],
                        "family": response["family"]
                        }
                    else:
                        results = {
                        "label": response["label"],
                        "status": response["status"],
                        "ip": query_ip}
                else:
                    print("the given ip not provied well...........")        

            else:
                print("starting submiting artifact attachment")
                response = submit_artifact_attachment(HYBRID_API_URL,HYBRID_SCAN_ENDPOINT,temp_artifact_file_path,header_H ,data ,body)
                if (response):
                    print("getting the results successfully.........")
                    if is_malicious(response):
                        results = {
                            "label": response["label"],
                            "scanners":response["scanners"],
                            "status": "danger"
                        }
                    else:
                        results = {
                            "label": response["label"],
                            "scanners":response["scanners"],
                            "status": "clean"            
                        }                    

            yield StatusMessage("done...")

            # Produce a FunctionResult with the results
            yield FunctionResult(results)
        except Exception:
            yield FunctionError()

        finally:
            remove_tmp_files(TEMP_FILES)
                