"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'add_comment_1' block
    add_comment_1(container=container)
    # call 'promote_to_case_4' block
    promote_to_case_4(container=container)

    return

def add_comment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_1() called")

    playbook_input_reason = phantom.collect2(container=container, datapath=["playbook_input:reason"])

    playbook_input_reason_values = [item[0] for item in playbook_input_reason]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=playbook_input_reason_values)

    set_severity_set_sensitivity_2(container=container)

    return


def set_severity_set_sensitivity_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_severity_set_sensitivity_2() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")
    phantom.set_sensitivity(container=container, sensitivity="red")

    container = phantom.get_container(container.get('id', None))

    pin_3(container=container)

    return


def pin_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_3() called")

    playbook_input_countries = phantom.collect2(container=container, datapath=["playbook_input:countries"])
    playbook_input_ip = phantom.collect2(container=container, datapath=["playbook_input:ip"])

    playbook_input_countries_values = [item[0] for item in playbook_input_countries]
    playbook_input_ip_values = [item[0] for item in playbook_input_ip]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=playbook_input_countries_values, message=playbook_input_ip_values, pin_style="grey", pin_type="card")

    prompt_1(container=container)

    return


def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = "Administrator"
    message = """Countries from IPs {0}"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:countries"
    ]

    # responses
    response_types = [
        {
            "prompt": "What do you think?",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Give us a reisk score",
            "options": {
                "type": "range",
                "min": 1,
                "max": 255,
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, response_types=response_types)

    return


def promote_to_case_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("promote_to_case_4() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.promote(container=container, template="Data Breach")

    container = phantom.get_container(container.get('id', None))

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.summary.responses.0","prompt_1:action_result.summary.responses.1"])

    prompt_1_summary_responses_0 = [item[0] for item in prompt_1_result_data]
    prompt_1_summary_responses_1 = [item[1] for item in prompt_1_result_data]

    output = {
        "thoughts": prompt_1_summary_responses_0,
        "some_reisk_score": prompt_1_summary_responses_1,
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