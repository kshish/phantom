"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'set_severity_1' block
    set_severity_1(container=container)

    return

def set_severity_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_severity_1() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")

    container = phantom.get_container(container.get('id', None))

    pin_2(container=container)

    return


def pin_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_2() called")

    playbook_input_myip = phantom.collect2(container=container, datapath=["playbook_input:myip"])
    playbook_input_msg = phantom.collect2(container=container, datapath=["playbook_input:msg"])

    playbook_input_myip_values = [item[0] for item in playbook_input_myip]
    playbook_input_msg_values = [item[0] for item in playbook_input_msg]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=playbook_input_myip_values, message=playbook_input_msg_values, pin_style="red", pin_type="card")

    prompt_1(container=container)

    return


def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = "Administrator"
    message = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:msg"
    ]

    # responses
    response_types = [
        {
            "prompt": "Please enter in a risk score (1=low, 100=high)",
            "options": {
                "type": "range",
                "min": 1,
                "max": 100,
            },
        },
        {
            "prompt": "Please enter a reason",
            "options": {
                "type": "message",
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, response_types=response_types)

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.summary.responses.0","prompt_1:action_result.summary.responses.1"])

    prompt_1_summary_responses_0 = [item[0] for item in prompt_1_result_data]
    prompt_1_summary_responses_1 = [item[1] for item in prompt_1_result_data]

    output = {
        "riskscore": prompt_1_summary_responses_0,
        "reason": prompt_1_summary_responses_1,
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