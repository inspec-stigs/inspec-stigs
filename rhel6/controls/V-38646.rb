# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38646 - The oddjobd service must not be running.'

control 'V-38646' do
  impact 0.1
  title 'The oddjobd service must not be running.'
  desc '
The "oddjobd" service may provide necessary functionality in some environments but it can be disabled if it is not needed. Execution of tasks by privileged programs, on behalf of unprivileged ones, has traditionally been a source of privilege escalation security issues.
'
  tag 'stig','V-38646'
  tag severity: 'low'
  tag checkid: 'C-46206r2_chk'
  tag fixid: 'F-43595r2_fix'
  tag version: 'RHEL-06-000266'
  tag ruleid: 'SV-50447r2_rule'
  tag fixtext: '
The "oddjobd" service exists to provide an interface and access control mechanism through which specified privileged tasks can run tasks for unprivileged client applications. Communication with "oddjobd" is through the system message bus. The "oddjobd" service can be disabled with the following commands:

# chkconfig oddjobd off
# service oddjobd stop
'
  tag checktext: '
To check that the "oddjobd" service is disabled in system boot configuration, run the following command:

# chkconfig "oddjobd" --list

Output should indicate the "oddjobd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

# chkconfig "oddjobd" --list
"oddjobd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "oddjobd" is disabled through current runtime configuration:

# service oddjobd status

If the service is disabled the command will return the following output:

oddjobd is stopped


If the service is running, this is a finding.
'

# START_DESCRIBE V-38646
  tag 'service','oddjobd'
  describe service('oddjobd') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
# END_DESCRIBE V-38646

end
