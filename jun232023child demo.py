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
    # call 'file_reputation_1' block
    file_reputation_1(container=container)

    return

@phantom.playbook_block()
def add_comment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_comment_1() called")

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

    set_severity_2(container=container)

    return


@phantom.playbook_block()
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

    pin_3(container=container)

    return


@phantom.playbook_block()
def pin_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("pin_3() called")

    playbook_input_countries = phantom.collect2(container=container, datapath=["playbook_input:countries"])
    playbook_input_ips = phantom.collect2(container=container, datapath=["playbook_input:ips"])

    playbook_input_countries_values = [item[0] for item in playbook_input_countries]
    playbook_input_ips_values = [item[0] for item in playbook_input_ips]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.pin(container=container, data=playbook_input_countries_values, message=playbook_input_ips_values, pin_style="red", pin_type="card")

    return


@phantom.playbook_block()
def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("file_reputation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.fileHash","artifact:*.id"])

    parameters = []

    # build parameters list for 'file_reputation_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "hash": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("file reputation", parameters=parameters, name="file_reputation_1", assets=["myvt"])

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    file_reputation_1_result_data = phantom.collect2(container=container, datapath=["file_reputation_1:action_result.summary.positives"])

    file_reputation_1_summary_positives = [item[0] for item in file_reputation_1_result_data]

    output = {
        "filehash_response": file_reputation_1_summary_positives,
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