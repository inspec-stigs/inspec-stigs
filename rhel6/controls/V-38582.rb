# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38582 - The xinetd service must be disabled if no network services utilizing it are enabled.'

control 'V-38582' do
  impact 0.5
  title 'The xinetd service must be disabled if no network services utilizing it are enabled.'
  desc '
The xinetd service provides a dedicated listener service for some programs, which is no longer necessary for commonly-used network services. Disabling it ensures that these uncommon services are not running, and also prevents attacks against xinetd itself.
'
  tag 'stig','V-38582'
  tag severity: 'medium'
  tag checkid: 'C-46140r2_chk'
  tag fixid: 'F-43530r2_fix'
  tag version: 'RHEL-06-000203'
  tag ruleid: 'SV-50383r2_rule'
  tag fixtext: '
The "xinetd" service can be disabled with the following commands: 

# chkconfig xinetd off
# service xinetd stop
'
  tag checktext: '
If network services are using the xinetd service, this is not applicable.

To check that the "xinetd" service is disabled in system boot configuration, run the following command: 

# chkconfig "xinetd" --list

Output should indicate the "xinetd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "xinetd" --list
"xinetd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "xinetd" is disabled through current runtime configuration: 

# service xinetd status

If the service is disabled the command will return the following output: 

xinetd is stopped


If the service is running, this is a finding.
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
