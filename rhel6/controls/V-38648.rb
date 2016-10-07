# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38648 - The qpidd service must not be running.'

control 'V-38648' do
  impact 0.1
  title 'The qpidd service must not be running.'
  desc '
The qpidd service is automatically installed when the "base" package selection is selected during installation. The qpidd service listens for network connections which increases the attack surface of the system. If the system is not intended to receive AMQP traffic then the "qpidd" service is not needed and should be disabled or removed.
'
  tag 'stig','V-38648'
  tag severity: 'low'
  tag checkid: 'C-46208r2_chk'
  tag fixid: 'F-43597r2_fix'
  tag version: 'RHEL-06-000267'
  tag ruleid: 'SV-50449r2_rule'
  tag fixtext: '
The "qpidd" service provides high speed, secure, guaranteed delivery services. It is an implementation of the Advanced Message Queuing Protocol. By default the qpidd service will bind to port 5672 and listen for connection attempts. The "qpidd" service can be disabled with the following commands: 

# chkconfig qpidd off
# service qpidd stop
'
  tag checktext: '
To check that the "qpidd" service is disabled in system boot configuration, run the following command: 

# chkconfig "qpidd" --list

Output should indicate the "qpidd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "qpidd" --list
"qpidd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "qpidd" is disabled through current runtime configuration: 

# service qpidd status

If the service is disabled the command will return the following output: 

qpidd is stopped


If the service is running, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
