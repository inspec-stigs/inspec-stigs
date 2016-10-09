# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38594 - The rshd service must not be running.'

control 'V-38594' do
  impact 1.0
  title 'The rshd service must not be running.'
  desc '
The rsh service uses unencrypted network communications, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network.
'
  tag 'stig','V-38594'
  tag severity: 'high'
  tag checkid: 'C-46152r2_chk'
  tag fixid: 'F-43542r3_fix'
  tag version: 'RHEL-06-000214'
  tag ruleid: 'SV-50395r2_rule'
  tag fixtext: '
The "rsh" service, which is available with the "rsh-server" package and runs as a service through xinetd, should be disabled. The "rsh" service can be disabled with the following command:

# chkconfig rsh off
'
  tag checktext: '
To check that the "rsh" service is disabled in system boot configuration, run the following command:

# chkconfig "rsh" --list

Output should indicate the "rsh" service has either not been installed, or has been disabled, as shown in the example below:

# chkconfig "rsh" --list
rsh off
OR
error reading information on service rsh: No such file or directory


If the service is running, this is a finding.
'

# START_DESCRIBE V-38594
  describe service('rsh') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
# END_DESCRIBE V-38594

end
