# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38672 - The netconsole service must be disabled unless required.'

control 'V-38672' do
  impact 0.1
  title 'The netconsole service must be disabled unless required.'
  desc '
The "netconsole" service is not necessary unless there is a need to debug kernel panics, which is not common.
'
  tag 'stig','V-38672'
  tag severity: 'low'
  tag checkid: 'C-46233r1_chk'
  tag fixid: 'F-43622r2_fix'
  tag version: 'RHEL-06-000289'
  tag ruleid: 'SV-50473r2_rule'
  tag fixtext: '
The "netconsole" service is responsible for loading the netconsole kernel module, which logs kernel printk messages over UDP to a syslog server. This allows debugging of problems where disk logging fails and serial consoles are impractical. The "netconsole" service can be disabled with the following commands:

# chkconfig netconsole off
# service netconsole stop
'
  tag checktext: '
To check that the "netconsole" service is disabled in system boot configuration, run the following command:

# chkconfig "netconsole" --list

Output should indicate the "netconsole" service has either not been installed, or has been disabled at all runlevels, as shown in the example below:

# chkconfig "netconsole" --list
"netconsole" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "netconsole" is disabled through current runtime configuration:

# service netconsole status

If the service is disabled the command will return the following output:

netconsole is stopped


If the service is running, this is a finding.
'

# START_DESCRIBE V-38672
  tag 'service','netconsole'
  describe service('netconsole') do
    it { should_not be_enabled }
    it { should_not be_running }
  end
# END_DESCRIBE V-38672

end
