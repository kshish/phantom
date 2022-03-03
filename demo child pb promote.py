"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'set_severity_promote_to_case_add_note_1' block
    set_severity_promote_to_case_add_note_1(container=container)

    return

def set_severity_promote_to_case_add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_severity_promote_to_case_add_note_1() called")

    playbook_input_country_name = phantom.collect2(container=container, datapath=["playbook_input:country_name"])

    playbook_input_country_name_values = [item[0] for item in playbook_input_country_name]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")
    phantom.promote(container=container, template="Suspicious Email")
    phantom.add_note(container=container, content=playbook_input_country_name_values, note_format="markdown", note_type="general", title="This is a note title")

    container = phantom.get_container(container.get('id', None))

    prompt_1(container=container)

    return


def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("prompt_1() called")

    # set user and message variables for phantom.prompt call

    user = "admin"
    message = """{0}\nCountry name {1} \n{0}"""

    # parameter list for template variable replacement
    parameters = [
        "playbook_input:myip",
        "playbook_input:a_list"
    ]

    # responses
    response_types = [
        {
            "prompt": "Please enter your thoughts",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Enter one more thought",
            "options": {
                "type": "message",
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=1, name="prompt_1", parameters=parameters, response_types=response_types)

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    prompt_1_result_data = phantom.collect2(container=container, datapath=["prompt_1:action_result.status","prompt_1:action_result.summary.responses.0","prompt_1:action_result.summary.responses.1"])

    prompt_1_result_item_0 = [item[0] for item in prompt_1_result_data]
    prompt_1_summary_responses_0 = [item[1] for item in prompt_1_result_data]
    prompt_1_summary_responses_1 = [item[2] for item in prompt_1_result_data]

    a_message_combined_value = phantom.concatenate(prompt_1_result_item_0, prompt_1_summary_responses_0)

    output = {
        "a_message": a_message_combined_value,
        "thought": prompt_1_summary_responses_1,
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