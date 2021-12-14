"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'format_1' block
    format_1(container=container)

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_1() called")

    template = """{0} is from {1}\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:ip",
        "playbook_input:country_name"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    playbook_input_ip = phantom.collect2(container=container, datapath=["playbook_input:ip"])
    format_1 = phantom.get_format_data(name="format_1")

    playbook_input_ip_values = [item[0] for item in playbook_input_ip]

    output = {
        "ip_and_country": format_1,
        "ip": playbook_input_ip_values,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return