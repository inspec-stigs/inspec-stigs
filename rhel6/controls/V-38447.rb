# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38447 - The system package management tool must verify contents of all files associated with packages.'

control 'V-38447' do
  impact 0.1
  title 'The system package management tool must verify contents of all files associated with packages.'
  desc '
The hash on important files like system executables should match the information given by the RPM database. Executables with erroneous hashes could be a sign of nefarious activity on the system.
'
  tag 'stig','V-38447','long','rpm'
  tag severity: 'low'
  tag checkid: 'C-46002r3_chk'
  tag fixid: 'F-43392r1_fix'
  tag version: 'RHEL-06-000519'
  tag ruleid: 'SV-50247r2_rule'
  tag fixtext: '
The RPM package management system can check the hashes of installed software packages, including many that are important to system security. Run the following command to list which files on the system have hashes that differ from what is expected by the RPM database:

# rpm -Va | grep \'^..5\'

A "c" in the second column indicates that a file is a configuration file, which may appropriately be expected to change. If the file that has changed was not expected to then refresh from distribution media or online repositories.

rpm -Uvh [affected_package]

OR

yum reinstall [affected_package]
'
  tag checktext: '
The following command will list which files on the system have file hashes different from what is expected by the RPM database.

# rpm -Va | awk \'$1 ~ /..5/ && $2 != "c"\'


If there is output, this is a finding.
'

# START_DESCRIBE V-38447
  describe command("rpm -Va | awk '$1 ~ /..5/ && $2 != \"c\"'") do
    its('stdout') { should eq '' }
  end
# END_DESCRIBE V-38447

end
