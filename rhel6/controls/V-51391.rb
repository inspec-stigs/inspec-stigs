# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-05-26
# description: The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: disa.stig_spt@mail.mil.
# impacts

title 'V-51391 - A file integrity baseline must be created.'

control 'V-51391' do
  impact 0.5
  title 'A file integrity baseline must be created.'
  desc '
For AIDE to be effective, an initial database of "known-good" information about files must be captured and it should be able to be verified against the installed files.
'
  tag 'stig','V-51391'
  tag severity: 'medium'
  tag checkid: 'C-53727r1_chk'
  tag fixid: 'F-56189r1_fix'
  tag version: 'RHEL-06-000018'
  tag ruleid: 'SV-65601r1_rule'
  tag fixtext: '
Run the following command to generate a new database:

# /usr/sbin/aide --init

By default, the database will be written to the file "/var/lib/aide/aide.db.new.gz". Storing the database, the configuration file "/etc/aide.conf", and the binary "/usr/sbin/aide" (or hashes of these files), in a secure location (such as on read-only media) provides additional assurance about their integrity. The newly-generated database can be installed as follows:

# cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

To initiate a manual check, run the following command:

# /usr/sbin/aide --check

If this check produces any unexpected output, investigate.
'
  tag checktext: '
To find the location of the AIDE database file, run the following command:

# grep DBDIR /etc/aide.conf

Using the defined values of the [DBDIR] and [database] variables, verify the existence of the AIDE database file:

# ls -l [DBDIR]/[database_file_name]

If there is no database file, this is a finding.
'

# START_DESCRIBE V-51391
  tag 'aide','aide.conf'
  describe file('/var/lib/aide/aide.db.gz') do
    it { should exist }
  end
  describe file('/etc/aide.conf') do
    its('content') { should match "@@define DBDIR /var/lib/aide" }
  end
# END_DESCRIBE V-51391

end
