"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'set_severity_2' block
    set_severity_2(container=container)

    return

def set_severity_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_severity_2() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")

    container = phantom.get_container(container.get('id', None))

    send_email_1(container=container)

    return


def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("send_email_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    playbook_input_someemailaddr = phantom.collect2(container=container, datapath=["playbook_input:someemailaddr"])
    playbook_input_mylistofips = phantom.collect2(container=container, datapath=["playbook_input:mylistofips"])

    parameters = []

    # build parameters list for 'send_email_1' call
    for playbook_input_someemailaddr_item in playbook_input_someemailaddr:
        for playbook_input_mylistofips_item in playbook_input_mylistofips:
            if playbook_input_someemailaddr_item[0] is not None and playbook_input_mylistofips_item[0] is not None:
                parameters.append({
                    "to": playbook_input_someemailaddr_item[0],
                    "body": playbook_input_mylistofips_item[0],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="send_email_1", assets=["myemailserver"], callback=prompt_1)

    return


def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = "admin"
    message = """Here's the email: {0}\nand here's the list:\n{1}"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:someemailaddr",
        "playbook_input:mylistofips"
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
            "prompt": "Please type in an IP",
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
        "thoughtsfromchildpbanalyst": prompt_1_summary_responses_0,
        "anip": prompt_1_summary_responses_1,
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