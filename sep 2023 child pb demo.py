"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'add_comment_1' block
    add_comment_1(container=container)

    return

@phantom.playbook_block()
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

    set_sensitivity_set_severity_set_status_2(container=container)

    return


@phantom.playbook_block()
def set_sensitivity_set_severity_set_status_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_sensitivity_set_severity_set_status_2() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_sensitivity(container=container, sensitivity="red")
    phantom.set_severity(container=container, severity="high")
    phantom.set_status(container=container, status="open")

    container = phantom.get_container(container.get('id', None))

    pin_3(container=container)

    return


@phantom.playbook_block()
def pin_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_3() called")

    playbook_input_country_list = phantom.collect2(container=container, datapath=["playbook_input:country_list"])

    playbook_input_country_list_values = [item[0] for item in playbook_input_country_list]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=playbook_input_country_list_values, message="IPs outside our list", pin_style="red", pin_type="card")

    prompt_3(container=container)

    return


@phantom.playbook_block()
def prompt_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_3() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """Here's the reason: {0}\n\n"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:reason"
    ]

    # responses
    response_types = [
        {
            "prompt": "What do you think of the reason?",
            "options": {
                "type": "message",
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="prompt_3", parameters=parameters, response_types=response_types)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    prompt_3_result_data = phantom.collect2(container=container, datapath=["prompt_3:action_result.summary.responses.0"])

    prompt_3_summary_responses_0 = [item[0] for item in prompt_3_result_data]

    output = {
        "thoughts": prompt_3_summary_responses_0,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return