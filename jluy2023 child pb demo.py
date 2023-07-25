"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'set_severity_pin_1' block
    set_severity_pin_1(container=container)

    return

@phantom.playbook_block()
def set_severity_pin_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_severity_pin_1() called")

    playbook_input_ips = phantom.collect2(container=container, datapath=["playbook_input:ips"])

    playbook_input_ips_values = [item[0] for item in playbook_input_ips]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")
    phantom.pin(container=container, data=playbook_input_ips_values, message="IPs outside our Countries list", pin_style="red", pin_type="card")

    container = phantom.get_container(container.get('id', None))

    add_comment_2(container=container)

    return


@phantom.playbook_block()
def add_comment_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_2() called")

    playbook_input_reason_for_high_severity = phantom.collect2(container=container, datapath=["playbook_input:reason_for_high_severity"])

    playbook_input_reason_for_high_severity_values = [item[0] for item in playbook_input_reason_for_high_severity]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment=playbook_input_reason_for_high_severity_values)

    prompt_1(container=container)

    return


@phantom.playbook_block()
def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """Reason for High severity: \n\n\n{0}"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:reason_for_high_severity"
    ]

    # responses
    response_types = [
        {
            "prompt": "What do you think",
            "options": {
                "type": "message",
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, response_types=response_types)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.summary.responses.0"])

    prompt_1_summary_responses_0 = [item[0] for item in prompt_1_result_data]

    output = {
        "their_thoughts": prompt_1_summary_responses_0,
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