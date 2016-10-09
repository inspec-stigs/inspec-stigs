# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38691 - The Bluetooth service must be disabled.'

control 'V-38691' do
  impact 0.5
  title 'The Bluetooth service must be disabled.'
  desc '
Disabling the "bluetooth" service prevents the system from attempting connections to Bluetooth devices, which entails some security risk. Nevertheless, variation in this risk decision may be expected due to the utility of Bluetooth connectivity and its limited range.
'
  tag 'stig','V-38691'
  tag severity: 'medium'
  tag checkid: 'C-46253r3_chk'
  tag fixid: 'F-43640r1_fix'
  tag version: 'RHEL-06-000331'
  tag ruleid: 'SV-50492r2_rule'
  tag fixtext: '
The "bluetooth" service can be disabled with the following command:

# chkconfig bluetooth off



# service bluetooth stop
'
  tag checktext: '
To check that the "bluetooth" service is disabled in system boot configuration, run the following command:

# chkconfig "bluetooth" --list

Output should indicate the "bluetooth" service has either not been installed or has been disabled at all runlevels, as shown in the example below:

# chkconfig "bluetooth" --list
"bluetooth" 0:off 1:off 2:off 3:off 4:off 5:off 6:off


If the service is configured to run, this is a finding.
'

# START_DESCRIBE V-38691
  tag 'service','bluetooth'
  describe service('bluetooth') do
    it { should_not be_enabled }
    it { should_not be_installed }
  end
# END_DESCRIBE V-38691

end
