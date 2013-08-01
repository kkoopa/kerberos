#include "kerberos_context.h"

Persistent<FunctionTemplate> KerberosContext::constructor_template;

KerberosContext::KerberosContext() : ObjectWrap() {
}

KerberosContext::~KerberosContext() {
}

KerberosContext* KerberosContext::New() {
  NanScope();

  Local<Object> obj = NanPersistentToLocal(constructor_template)->GetFunction()->NewInstance();
  KerberosContext *kerberos_context = ObjectWrap::Unwrap<KerberosContext>(obj);
  return kerberos_context;
}

NAN_METHOD(KerberosContext::New) {
  NanScope();
  // Create code object
  KerberosContext *kerberos_context = new KerberosContext();
  // Wrap it
  kerberos_context->Wrap(args.This());
  // Return the object
  NanReturnValue(args.This());
}

static Persistent<String> response_symbol;

void KerberosContext::Initialize(Handle<Object> target) {
  // Grab the scope of the call from Node
  NanScope();
  // Define a new function template
  Local<FunctionTemplate> t = FunctionTemplate::New(New);
  t->InstanceTemplate()->SetInternalFieldCount(1);
  t->SetClassName(String::NewSymbol("KerberosContext"));

  // Property symbols
  Local<String> response_sym = String::NewSymbol("response");
  NanAssignPersistent(String, response_symbol, response_sym);

  // Getter for the response
  t->InstanceTemplate()->SetAccessor(response_sym, ResponseGetter);

  NanAssignPersistent(FunctionTemplate, constructor_template, t);

  // Set up the Symbol for the Class on the Module
  target->Set(String::NewSymbol("KerberosContext"), t->GetFunction());
}

//
// Response Setter / Getter
NAN_GETTER(KerberosContext::ResponseGetter) {
  NanScope();
  gss_client_state *state;

  // Unpack the object
  KerberosContext *context = ObjectWrap::Unwrap<KerberosContext>(args.Holder());
  // Let's grab the response
  state = context->state;
  // No state no response
  if(state == NULL || state->response == NULL) NanReturnValue(Null());
  // Return the response
  NanReturnValue(String::New(state->response));
}
