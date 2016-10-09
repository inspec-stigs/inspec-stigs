# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38641 - The atd service must be disabled.'

control 'V-38641' do
  impact 0.1
  title 'The atd service must be disabled.'
  desc '
The "atd" service could be used by an unsophisticated insider to carry out activities outside of a normal login session, which could complicate accountability. Furthermore, the need to schedule tasks with "at" or "batch" is not common.
'
  tag 'stig','V-38641'
  tag severity: 'low'
  tag checkid: 'C-46201r2_chk'
  tag fixid: 'F-43590r2_fix'
  tag version: 'RHEL-06-000262'
  tag ruleid: 'SV-50442r2_rule'
  tag fixtext: '
The "at" and "batch" commands can be used to schedule tasks that are meant to be executed only once. This allows delayed execution in a manner similar to cron, except that it is not recurring. The daemon "atd" keeps track of tasks scheduled via "at" and "batch", and executes them at the specified time. The "atd" service can be disabled with the following commands:

# chkconfig atd off
# service atd stop
'
  tag checktext: '
If the system uses the "atd" service, this is not applicable.

To check that the "atd" service is disabled in system boot configuration, run the following command:

# chkconfig "atd" --list

Output should indicate the "atd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

# chkconfig "atd" --list
"atd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "atd" is disabled through current runtime configuration:

# service atd status

If the service is disabled the command will return the following output:

atd is stopped


If the service is running, this is a finding.
'

# START_DESCRIBE V-38641
  tag 'service','atd'
  describe service('atd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
# END_DESCRIBE V-38641

end
