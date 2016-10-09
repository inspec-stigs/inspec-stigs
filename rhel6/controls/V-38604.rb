# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38604 - The ypbind service must not be running.'

control 'V-38604' do
  impact 0.5
  title 'The ypbind service must not be running.'
  desc '
Disabling the "ypbind" service ensures the system is not acting as a client in a NIS or NIS+ domain.
'
  tag 'stig','V-38604'
  tag severity: 'medium'
  tag checkid: 'C-46162r2_chk'
  tag fixid: 'F-43552r2_fix'
  tag version: 'RHEL-06-000221'
  tag ruleid: 'SV-50405r2_rule'
  tag fixtext: '
The "ypbind" service, which allows the system to act as a client in a NIS or NIS+ domain, should be disabled. The "ypbind" service can be disabled with the following commands:

# chkconfig ypbind off
# service ypbind stop
'
  tag checktext: '
To check that the "ypbind" service is disabled in system boot configuration, run the following command:

# chkconfig "ypbind" --list

Output should indicate the "ypbind" service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

# chkconfig "ypbind" --list
"ypbind" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "ypbind" is disabled through current runtime configuration:

# service ypbind status

If the service is disabled the command will return the following output:

ypbind is stopped


If the service is running, this is a finding.
'

# START_DESCRIBE V-38604
  describe service('ypbind') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
# END_DESCRIBE V-38604

end
