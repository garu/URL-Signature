package URL::Signature::Query;

use strict;
use warnings;
use parent 'URL::Signature';
use Params::Util qw( _STRING );

our $VERSION = '0.01';

sub new {
    my ($class, %attrs) = @_;
    return $class->SUPER::new( %attrs, format => 'query' );
}


sub BUILD {
    my $self = shift;
    $self->{'as'} = 'k' unless exists $self->{'as'};
    Carp::croak(q[in 'query' format, 'as' needs to be a valid string])
        unless defined _STRING($self->{'as'});
    return;
}


sub extract {
    my ($self, $uri) = @_;
    my $code = $uri->query_param_delete( $self->{as} );
    return ($code, $uri);
}


sub append {
    my ($self, $uri, $code) = @_;
    my $varname = $self->{as};
    my $code_check = $uri->query_param_delete($varname);
    Carp::croak("variable '$varname' (reserved for auth code) found in path")
        if $code_check;

    $uri->query_param_append( $varname => $code );
    return $uri;
}


42;
__END__

=head1 NAME

URL::Signature::Query - Sign your URL with a query parameter

=head1 SYNOPSIS

  use URL::Signature::Query;
  my $signer = URL::Signature::Path->new( key => 'my-secret-key' );

  my $url = $signer->sign('/some/path');


or, from within URL::Signature:

  use URL::Signature;
  my $signer = URL::Signature->new(
    key    => 'my-secret-key',
    format => 'query',
  );


=head1 SEE ALSO

L<URL::Signature>


