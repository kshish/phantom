"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'read_list' block
    read_list(container=container)

    return

def read_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('read_list() called')
    input_parameter_0 = ""

    read_list__peer_list = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    # Fetch list name from container data
    peer_list_name = phantom.get_container(container['id'])['data']["peer_list"]
    
    phantom.debug("peer list value ind data list: <<%s>>" % phantom.get_container(container['id'])['data']["peer_list"])
    
    phantom.debug("peer_list_name = <<%s>>" % peer_list_name)
    
    sta, msg, read_list__peer_list = phantom.get_list(list_name=peer_list_name)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='read_list:peer_list', value=json.dumps(read_list__peer_list))
    create_containers(container=container)

    return

def create_containers(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('create_containers() called')
    read_list__peer_list = json.loads(phantom.get_run_data(key='read_list:peer_list'))

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    for server in read_list__peer_list:
        if server[2] in ["critical","high"]:
            phantom.debug("%s is priority %s" % (server[0],server[2]))
            status, message, cid = phantom.create_container(name="Possible server malware", label="events")
            #phantom.set_severity(cid, "high")
            phantom.add_artifact(container=cid, raw_data={}, cef_data={"sourceAddress":server[0]}, label="infection", name="Possibly infected host", severity="high", artifact_type="host")

    ################################################################################
    ## Custom Code End
    ################################################################################

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return