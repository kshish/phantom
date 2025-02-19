"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'pin_1' block
    pin_1(container=container)

    return

@phantom.playbook_block()
def pin_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("pin_1() called")

    playbook_input_countries = phantom.collect2(container=container, datapath=["playbook_input:countries"])

    playbook_input_countries_values = [item[0] for item in playbook_input_countries]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=playbook_input_countries_values, message="IP(s) not in our list", pin_style="red", pin_type="card")

    add_comment_2(container=container)

    return


@phantom.playbook_block()
def add_comment_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
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
    promote_to_case_3(container=container)
    set_severity_4(container=container)

    return


@phantom.playbook_block()
def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """{0}\n\n{1}"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:reason_for_high_severity",
        "playbook_input:formatted_list_of_ips_and_countries"
    ]

    # responses
    response_types = [
        {
            "prompt": "Please provide a risk score",
            "options": {
                "type": "range",
                "min": 111,
                "max": 211,
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, response_types=response_types)

    return


@phantom.playbook_block()
def promote_to_case_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("promote_to_case_3() called")

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


@phantom.playbook_block()
def set_severity_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("set_severity_4() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.summary.responses.0"])

    prompt_1_summary_responses_0 = [item[0] for item in prompt_1_result_data]

    output = {
        "risk_score": prompt_1_summary_responses_0,
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