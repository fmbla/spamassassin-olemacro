package Mail::SpamAssassin::Plugin::OLEMacro;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Util;
use Archive::Zip qw( :ERROR_CODES :CONSTANTS );
use IO::String;

use strict;
use warnings;
use re 'taint';

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

our $VERSION = '0.2';

my $marker1 = "\xd0\xcf\x11\xe0";
my $marker2 = "\x00\x41\x74\x74\x72\x69\x62\x75\x74\x00";

my $macrotypes = qr/(?:docm|dotm|potm|ppst|pptm|xlsb|xlsm|xltm)$/;
my $exts = qr/(?:doc|dot|pot|pps|ppt|xls|xlt)$/;

my $max_mime = 5;
my $max_zip = 5;
my $zip_num_of_bytes = 512000;

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule("check_olemacro");

  return $self;
}

sub dbg {
  Mail::SpamAssassin::Plugin::dbg ("OLEMacro: @_");
}

sub check_olemacro {
  my ($self,$pms,$body,$name) = @_;

  _check_attachments(@_) unless exists $pms->{olemacro_exists};

  return $pms->{olemacro_exists};
}

sub _check_attachments {

  my ($self,$pms,$body,$name) = @_;

  my $mimec = 0;

  $pms->{olemacro_exists} = 0;

  foreach my $part ($pms->{msg}->find_parts(qr/./, 1)) {
    my ($ctype, $boundary, $charset, $name) =
      Mail::SpamAssassin::Util::parse_content_type($part->get_header('content-type'));

    my $cte = lc($part->get_header('content-transfer-encoding') || '');
    my $data = undef;

    next unless ($cte =~ /^(?:base64)$/);

    $name = lc($name || '');
    $ctype = lc $ctype;

    dbg("Found attachment with name $name of type $ctype ");

    # if name is macrotype - return true
    if ($name =~ $macrotypes) {
      $pms->{olemacro_exists} = 1;
      return 1;
    }

    # if name is ext type - check and return true if needed
    if ($name =~ $exts) {
      $data = $part->decode() unless defined $data;
      if (_check_markers($data)) {
        $pms->{olemacro_exists} = 1;
        return 1;
      }
    }

    # check for zip
    my $tdata = $part->decode(6);

    if (_is_zip_file($name, $tdata)) {
      dbg("$name is a zip file");
      $data = $part->decode() unless defined $data;
      if (_check_zip($data)) {
        $pms->{olemacro_exists} = 1;
        return 1;
      }
    }

    $mimec += 1 if defined $data;
    last if $mimec > $max_mime;

  }
  return 0;
}

sub _check_zip {
  my ($data) = @_;

  my $SH = IO::String->new($data);

  Archive::Zip::setErrorHandler( \&_zip_error_handler );
  my $zip = Archive::Zip->new();
  if($zip->readFromFileHandle( $SH ) != AZ_OK){
    dbg("cannot read zipfile");
    # as we cannot read it its not a zip (or too big/corrupted)
    # so skip processing.
    return 0;
  }

  my $filec = 0;

  my @members = $zip->members();
  foreach my $member (@members){
    my $mname = lc $member->fileName();
    my $data = undef;
    my $status = undef;

    return 1 if $mname =~ $macrotypes;

    if ($mname =~ $exts) {
      ( $data, $status ) = $member->contents() unless defined $data;
      next unless $status == AZ_OK;
      if (_check_markers($data)) {
        return 1;
      }
    }

    if ($mname eq "[content_types].xml") {
      ( $data, $status ) = $member->contents() unless defined $data;
      next unless $status == AZ_OK;
      if ($data =~ /ContentType=["']application\/vnd.ms-office.vbaProject["']/i){
        dbg('vbaProject reference in xml');
        return 1;
      }
    }

    ( $data, $status ) = $member->contents() unless defined $data;
    next unless $status == AZ_OK;

    if (_is_zip_file($mname, $data)) {
      dbg("$mname is a zip file");
      if (_check_zip($data)) {
        return 1;
      }
    }

    $filec+=1 if defined $data;
    last if $filec > $max_zip;
  }
}

sub _is_zip_file {
  my ($name, $data) = @_;
  if (index($data, 'PK') == 0) {
    return 1;
  } else {
    return($name =~ /(?:zip)$/);    
  }
}

sub _check_markers {
  my ($data) = @_;
  if (index($data, $marker1) == 0 && index($data, $marker2) > -1) {
    dbg('Marker found');
    return 1;
  }
}

sub _zip_error_handler {

}

1;
