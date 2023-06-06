from datetime import timedelta

import pytest
from helpers import faker

from nio.crypto import KVF, KVFState, OlmDevice
from nio.events import (
    KeyVerificationCancel,
    KeyVerificationDone,
    KeyVerificationReady,
    KeyVerificationRequest,
)
from nio.exceptions import LocalProtocolError

alice_id = "@alice:example.org"
alice_device_id = "JLAFKJWSCS"
alice_keys = faker.olm_key_pair()

bob_id = "@bob:example.org"
bob_device_id = "JLAFKJWSRS"
bob_device_id_2 = "JLAFKJWSRX"
bob_keys = faker.olm_key_pair()

alice_device = OlmDevice(alice_id, alice_device_id, alice_keys)

bob_device = OlmDevice(bob_id, bob_device_id, bob_keys)
bob_device_2 = OlmDevice(bob_id, bob_device_id_2, bob_keys)


# TODO: SAS needed?
class TestClass:
    def test_kvf_creation(self):
        alice = KVF(alice_device_id)
        assert alice.transaction_id is not None
        assert alice.done == False

    def test_kvf_request(self):
        alice = KVF(alice_device_id)
        assert alice.state == KVFState.CREATED

        request = {
            "sender": alice_id,
            "content": alice.request_verification(bob_device).content,
        }
        request_event = KeyVerificationRequest.from_dict(request)
        assert isinstance(request_event, KeyVerificationRequest)
        assert alice.state == KVFState.REQUESTED

        bob = KVF.from_key_verification_request(
            bob_device_id, alice.transaction_id, alice_device
        )
        with pytest.raises(LocalProtocolError):
            bob.request_verification(alice_device)

        assert bob.state == KVFState.REQUESTED

    def test_kvf_ready(self):
        alice = KVF(alice_device_id)
        alice.request_verification(bob_device)
        bob = KVF.from_key_verification_request(
            bob_device_id, alice.transaction_id, alice_device
        )

        ready = {"sender": bob_id, "content": bob.accept_verification_request().content}
        ready_event = KeyVerificationReady.from_dict(ready)
        assert isinstance(ready_event, KeyVerificationReady)
        assert bob.state == KVFState.READY
        alice.verification_request_accepted(bob_device)
        assert alice.state == KVFState.READY

    def test_kvf_cancellation(self):
        alice = KVF(alice_device_id)
        alice.request_verification(bob_device)
        bob = KVF.from_key_verification_request(
            bob_device_id, alice.transaction_id, alice_device
        )

        bob.accept_verification_request()
        alice.verification_request_accepted(bob_device)
        assert alice.state == KVFState.READY
        assert bob.state == KVFState.READY

        messages = bob.cancel_verification(alice_device)
        assert len(messages) == 1
        cancel = {"sender": bob_id, "content": messages[0].content}
        cancel_event = KeyVerificationCancel.from_dict(cancel)
        assert isinstance(cancel_event, KeyVerificationCancel)
        assert bob.state == KVFState.CANCELED
        messages = alice.process_cancellation()
        assert len(messages) == 1
        cancel = {"sender": bob_id, "content": messages[0].content}
        cancel_event = KeyVerificationCancel.from_dict(cancel)
        assert isinstance(cancel_event, KeyVerificationCancel)
        assert alice.state == KVFState.CANCELED

    def test_kvf_done(self):
        alice = KVF(alice_device_id)
        alice.request_verification(bob_device)
        bob = KVF.from_key_verification_request(
            bob_device_id, alice.transaction_id, alice_device
        )

        bob.accept_verification_request()
        alice.verification_request_accepted(bob_device)
        assert alice.state == KVFState.READY
        assert alice.done == False
        done = {"sender": alice_id, "content": alice.verification_done().content}
        done_event = KeyVerificationDone.from_dict(done)
        assert isinstance(done_event, KeyVerificationDone)
        assert alice.state == KVFState.DONE
        assert alice.done == True

    def test_kvf_local_errors(self):
        alice = KVF(alice_device_id)

        with pytest.raises(LocalProtocolError):
            alice.accept_verification_request()

        with pytest.raises(LocalProtocolError):
            alice.verification_done()

        alice.request_verification(bob_device)
        alice.request_verification(bob_device_2)
        bob = KVF.from_key_verification_request(
            bob_device_id, alice.transaction_id, alice_device
        )

        with pytest.raises(LocalProtocolError):
            bob.request_verification(alice_device)

        bob.accept_verification_request()
        with pytest.raises(LocalProtocolError):
            alice.verification_request_accepted(alice_device)

        alice.verification_request_accepted(bob_device)
        with pytest.raises(LocalProtocolError):
            alice.request_verification(bob_device)

        alice.verification_done()
        with pytest.raises(LocalProtocolError):
            alice.verification_done()

        bob.cancel_verification(alice_device)
        with pytest.raises(LocalProtocolError):
            bob.verification_done()
