open Ctypes
open Tls
open Foreign

let () = Nocrypto_entropy_unix.initialize ()

exception Tls_alert   of Tls.Packet.alert_type
exception Tls_failure of Tls.Engine.failure

type t = {
  mutable state  : [ `Active of Tls.Engine.state
                   | `Eof
                   | `Error of exn ] ;
  mutable hanging : [ `Read | `Write | `None ];
  mutable input_buffer : Cstruct.t option;
  mutable output_buffer : Cstruct.t option;
  mutable linger : Cstruct.t option ;
}

let handshake_state_e = [
  ("TLS_HANDSHAKE_STOPPED", (Int64.of_int 0));
  ("TLS_HANDSHAKE_EOF", (Int64.of_int 1));
  ("TLS_HANDSHAKE_ACTIVE", (Int64.of_int 2))
]

let int_of_handshake_state = function
  | `Stopped -> 0
  | `Eof -> 1
  | `Active -> 2

let handshake_state_of_int = function
  | 0 -> `Stopped
  | 1 -> `Eof
  | 2 -> `Active
  | _ -> assert false

let tls_handshake_state_typ = Ctypes.view ~read:handshake_state_of_int ~write:int_of_handshake_state Ctypes.int

let state_e = [
  ("TLS_ACTIVE", (Int64.of_int 0));
  ("TLS_EOF", (Int64.of_int 1));
  ("TLS_ERROR", (Int64.of_int 2));
  ("TLS_READ_READY", (Int64.of_int 3));
  ("TLS_WRITE_READY", (Int64.of_int 4))
]

let int_of_state = function
  | `Active -> 0
  | `Eof -> 1
  | `Error -> 2
  | `Read -> 3
  | `Write -> 4

let state_of_int = function
  | 0 -> `Active
  | 1 -> `Eof
  | 2 -> `Error
  | 3 -> `Read
  | 4 -> `Write
  | _ -> assert false

let tls_state_typ = Ctypes.view ~read:state_of_int ~write:int_of_state Ctypes.int

let conf_typedef = Ctypes.typedef void "TlsConf"
let client_typedef = Ctypes.typedef void "TlsClient"

let tls_client_typ = Ctypes.view ~read:Ctypes.Root.get ~write:Ctypes.Root.create (ptr client_typedef)
let tls_conf_typ = Ctypes.view ~read:Ctypes.Root.get ~write:Ctypes.Root.create (ptr conf_typedef)

type tls_output
let tls_output : tls_output structure typ = structure "TlsOutput"
let tls_output_len = field tls_output "len" int
let tls_output_buf = field tls_output "buffer" (ptr char)
let () = seal tls_output

(* TODO: move this to C *)

let load_file f =
  let ic = open_in f in
  let n = in_channel_length ic in
  let s = Bytes.create n in
  really_input ic s 0 n;
  close_in ic;
  (Cstruct.of_string s)

let private_of_pems cert priv_key =
  let open X509.Encoding.Pem in
  let certs = Certificate.of_pem_cstruct (load_file cert) in
  let pk =
    let pem = load_file priv_key in
    match Private_key.of_pem_cstruct1 pem with
    | `RSA key -> key in
  certs, pk

let rec read_react t =

  let handle tls buf =
    match
      Tls.Engine.handle_tls tls buf
    with
    | `Ok (state', `Response resp, `Data data) ->
      let state' = match state' with
        | `Ok tls -> `Active tls
        | `Eof -> `Eof
        | `Alert a -> `Error (Tls_alert a) in
      let () = t.state <- state' in
      (match resp with
       | Some cs -> t.output_buffer <- (Some cs); t.hanging <- `Write;
       | None -> ());
      (`Ok data)
    | `Fail (alert, `Response resp) ->
      (t.state <- `Error (Tls_failure alert);
       t.output_buffer <- (Some resp); t.hanging <- `Write;
       read_react t) in
  match t.state with
  | `Error e -> assert false
  | `Eof -> `Eof
  | `Active _ ->
    match t.input_buffer with
    | Some buf ->
      (match (t.state, Cstruct.len buf) with
      | (`Active _, 0) -> t.state <- `Eof; `Eof
      | (`Active tls, n) -> handle tls buf
      | _ -> assert false)
    | None -> t.hanging <- `Read; `Stopped

let rec tls_do_handshake t =
  let push_linger t mcs =
    let open Tls.Utils.Cs in
    match (mcs, t.linger) with
    | (None, _) -> ()
    | (scs, None) -> t.linger <- scs
    | (Some cs, Some l) -> t.linger <- Some (l <+> cs)
  in
  match t.state with
  | `Active tls when Tls.Engine.can_handle_appdata tls -> `Active
  | _ ->
    match read_react t with
    | `Eof -> `Eof
    | `Ok cs -> (push_linger t cs;
                 match t.output_buffer with
                 | None -> tls_do_handshake t
                 | Some _ -> `Stopped)
    | `Stopped -> t.input_buffer <- None; `Stopped

let tls_client_config cert priv_key =
  let authenticator = X509.Authenticator.null in
  let certificates = `Single (private_of_pems cert priv_key) in
  Tls.Config.client ~authenticator ~certificates ()

let tls_client config host =
  let config' = Tls.Config.peer config host in
  let (tls, init) = Tls.Engine.client config' in
  {
    state = `Active tls;
    hanging = `Write;
    linger = None;
    input_buffer = None;
    output_buffer = Some init;
  }

let tls_get_output_buffer t =
  match t.output_buffer with
  | None -> assert false
  | Some c ->
    let len = Cstruct.len c in
    let cc = Cstruct.to_bigarray c in
    let strct = make tls_output in
    setf strct tls_output_len len;
    setf strct tls_output_buf (bigarray_start array1 cc);
    strct

let tls_write_done t written =
  t.input_buffer <- None;
  t.output_buffer <- None;
  t.hanging <- `None

let tls_read_done t buf size =
  let ba = Ctypes.bigarray_of_ptr array1 size Bigarray.char buf in
  let cs = Cstruct.of_bigarray ba in
  t.input_buffer <- Some cs;
  t.hanging <- `None

let tls_get_state t =
  match t.state with
  | `Eof -> `Eof
  | `Error _ -> `Error
  | `Active _ ->
    (match t.hanging with
     | `None -> `Active
     | `Write -> `Write
     | `Read -> `Read)

let tls_prepare_appdata t buf size =
  let ba = Ctypes.bigarray_of_ptr array1 size Bigarray.char buf in
  let css = Cstruct.of_bigarray ba in
  match t.state with
  | `Error err  -> ()
  | `Eof        -> ()
  | `Active tls ->
    match
      Tls.Engine.send_application_data tls [css]
    with
    | Some (tls, tlsdata) ->
      ( t.state <- `Active tls ; t.output_buffer <- Some tlsdata; t.hanging <- `Write )
    | None -> ()

let tls_received_appdata t buf size =

  let writeout res =
    let open Cstruct in
    let ba = Ctypes.bigarray_of_ptr array1 size Bigarray.char buf in
    let cs = of_bigarray ba in
    let rlen = len res in
    let n    = min (len cs) rlen in
    blit res 0 cs 0 n ;
    t.linger <-
      (if n < rlen then Some (sub res n (rlen - n)) else None) ;
    n in

  match t.linger with
  | Some res -> writeout res
  | None     ->
    match read_react t with
    | `Eof           -> -1
    | `Ok None       -> 0
    | `Ok (Some res) -> writeout res
    | `Stopped -> 0

module Stubs (I : Cstubs_inverted.INTERNAL) =
struct

  let () = I.typedef void "TlsConf"

  let () = I.typedef void "TlsClient"

  let () = I.enum handshake_state_e (Ctypes.typedef Ctypes.int "enum TlsHandshakeState")

  let () = I.enum state_e (Ctypes.typedef Ctypes.int "enum TlsState")

  let () = I.structure tls_output

  let () = I.internal
      "tls_client_config" (string @-> string @-> returning tls_conf_typ) tls_client_config

  let () = I.internal
      "tls_client" (tls_conf_typ @-> string @-> returning tls_client_typ) tls_client

  let () = I.internal
      "tls_do_handshake" (tls_client_typ @-> returning tls_handshake_state_typ) tls_do_handshake

  let () = I.internal
      "tls_get_output_buffer" (tls_client_typ @-> returning tls_output) tls_get_output_buffer

  let () = I.internal
      "tls_write_done" (tls_client_typ @-> int @-> returning void) tls_write_done

  let () = I.internal
      "tls_read_done" (tls_client_typ @-> (ptr char) @-> int @-> returning void) tls_read_done

  let () = I.internal
      "tls_get_state" (tls_client_typ @-> returning tls_state_typ) tls_get_state

  let () = I.internal
      "tls_prepare_appdata" (tls_client_typ @-> (ptr char) @-> int @-> returning void) tls_prepare_appdata

  let () = I.internal
      "tls_received_appdata" (tls_client_typ @-> (ptr char) @-> int @-> returning int) tls_received_appdata
end
