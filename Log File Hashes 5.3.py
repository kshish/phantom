"""

"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'decision_1' block
    decision_1(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["playbook_input:hash", "in", "custom_list:Log File Hashes"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        add_comment_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_to_list_add_comment_1(action=action, success=success, container=container, results=results, handle=handle)

    return


def add_to_list_add_comment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_to_list_add_comment_1() called")

    playbook_input_hash = phantom.collect2(container=container, datapath=["playbook_input:hash"])

    playbook_input_hash_values = [item[0] for item in playbook_input_hash]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_list(list_name="Log File Hashes", values=playbook_input_hash_values)
    phantom.comment(container=container, comment="File hash has been not been observed before")

    new_hash_content(container=container)

    return


def add_comment_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_2() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="File hash has been observed before")

    old_hash_content(container=container)

    return


def new_hash_content(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("new_hash_content() called")

    template = """This file has not been oberved before"""

    # parameter list for template variable replacement
    parameters = [
        ""
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="new_hash_content")

    join_concatenate_hash_status(container=container)

    return


def old_hash_content(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("old_hash_content() called")

    template = """This file has been observed before"""

    # parameter list for template variable replacement
    parameters = [
        ""
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="old_hash_content")

    join_concatenate_hash_status(container=container)

    return


def join_concatenate_hash_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_concatenate_hash_status() called")

    # call connected block "concatenate_hash_status"
    concatenate_hash_status(container=container, handle=handle)

    return


def concatenate_hash_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("concatenate_hash_status() called")

    template = """{0} {1}\n"""

    # parameter list for template variable replacement
    parameters = [
        "new_hash_content:formatted_data",
        "old_hash_content:formatted_data"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="concatenate_hash_status")

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    concatenate_hash_status = phantom.get_format_data(name="concatenate_hash_status")

    output = {
        "hash_status": concatenate_hash_status,
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