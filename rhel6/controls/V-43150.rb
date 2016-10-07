# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-43150 - The login user list must be disabled.'

control 'V-43150' do
  impact 0.5
  title 'The login user list must be disabled.'
  desc '
Leaving the user list enabled is a security risk since it allows anyone with physical access to the system to quickly enumerate known user accounts without logging in.
'
  tag 'stig','V-43150'
  tag severity: 'medium'
  tag checkid: 'C-49197r4_chk'
  tag fixid: 'F-48722r2_fix'
  tag version: 'RHEL-06-000527'
  tag ruleid: 'SV-55880r2_rule'
  tag fixtext: '
In the default graphical environment, users logging directly into the system are greeted with a login screen that displays all known users. This functionality should be disabled.

Run the following command to disable the user list:

$ sudo gconftool-2 --direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type bool --set /apps/gdm/simple-greeter/disable_user_list true
'
  tag checktext: '
If the GConf2 package is not installed, this is not applicable.

To ensure the user list is disabled, run the following command:

$ gconftool-2 --direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--get /apps/gdm/simple-greeter/disable_user_list

The output should be "true". If it is not, this is a finding. 
'

# START_CHECKS
  # describe file('/etc') do
  #  it { should be_directory }
  #end
# END_CHECKS
end
