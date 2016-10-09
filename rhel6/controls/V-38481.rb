# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-38481 - System security patches and updates must be installed and up-to-date.'

control 'V-38481' do
  impact 0.5
  title 'System security patches and updates must be installed and up-to-date.'
  desc '
Installing software updates is a fundamental mitigation against the exploitation of publicly-known vulnerabilities.
'
  tag 'stig','V-38481','yum','check-update'
  tag severity: 'medium'
  tag checkid: 'C-46036r1_chk'
  tag fixid: 'F-43426r1_fix'
  tag version: 'RHEL-06-000011'
  tag ruleid: 'SV-50281r1_rule'
  tag fixtext: '
If the system is joined to the Red Hat Network, a Red Hat Satellite Server, or a yum server, run the following command to install updates:

# yum update

If the system is not configured to use one of these sources, updates (in the form of RPM packages) can be manually downloaded from the Red Hat Network and installed using "rpm".
'
  tag checktext: '
If the system is joined to the Red Hat Network, a Red Hat Satellite Server, or a yum server which provides updates, invoking the following command will indicate if updates are available:

# yum check-update

If the system is not configured to update from one of these sources, run the following command to list when each package was last updated:

$ rpm -qa -last

Compare this to Red Hat Security Advisories (RHSA) listed at https://access.redhat.com/security/updates/active/ to determine whether the system is missing applicable security and bugfix  updates.
If updates are not installed, this is a finding.
'

# START_DESCRIBE V-38481
  if os[:family] == 'redhat'
    describe command('yum check-update') do
      its('exit_status') { should eq 0 }
    end
  elsif os[:family] == 'debian'
    describe command('/usr/lib/update-notifier/apt-check -p') do
      its('stdout') { should eq '' }
    end
  end
# END_DESCRIBE V-38481

end
