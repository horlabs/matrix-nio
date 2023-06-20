# -*- coding: utf-8 -*-

# Copyright © 2019 Damir Jelić <poljar@termina.org.uk>
#
# Permission to use, copy, modify, and/or distribute this software for
# any purpose with or without fee is hereby granted, provided that the
# above copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
# RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
# CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from __future__ import annotations

from enum import Enum, auto
from time import time_ns
from typing import List, Optional, Tuple
from uuid import uuid4

from ..crypto.device import OlmDevice
from ..crypto.sas import Sas
from ..event_builders import ToDeviceMessage
from ..exceptions import LocalProtocolError


class KVFState(Enum):
    """Key Verification Framework enum.

    This enum tracks the current state of our verification process.
    """

    CREATED = auto()
    REQUESTED = auto()
    READY = auto()
    CANCELED = auto()
    DONE = auto()


# TODO: Documentation
class KeyVerificationFramework:
    """Matrix Short Authentication String class.

    This class implements a state machine to provide the framework for device
    verifications using any verification method.

    Attributes:
        we_requested_it (bool): Is true if the verification request was send
            by us, otherwise false.
        TODO

    Args:
        own_device (str): The device id of our own user.
        transaction_id (str, optional): A string that will uniquely identify
            this verification process. A random and unique string will be
            generated if one isn't provided.

    """

    _user_cancel_error = ("m.user", "Canceled by user")
    _user_accepted_reason = (
        "m.accepted",
        "Key verification request was accepted by another device.",
    )

    # TODO: Possible verification methods as arg?
    def __init__(self, own_device: str, transaction_id: Optional[str] = None):
        self.state = KVFState.CREATED
        self.own_device = own_device
        self.devices = []
        self.we_requested_it = True
        if transaction_id is None:
            self.transaction_id = str(uuid4())
        else:
            self.transaction_id = transaction_id

    @classmethod
    def from_key_verification_request(
        cls, own_device: str, transaction_id: str, requesting_device: OlmDevice
    ) -> KeyVerificationFramework:
        obj = cls(own_device, transaction_id)
        obj.we_requested_it = False
        obj.state = KVFState.REQUESTED
        obj.devices.append(requesting_device)

        return obj

    # TODO: timeout etc?

    @property
    def done(self) -> bool:
        """Is the verification request done."""
        return self.state == KVFState.DONE

    @property
    def canceled(self) -> bool:
        """Is the verification request canceled."""
        return self.state == KVFState.CANCELED

    def request_verification(self, device: OlmDevice) -> ToDeviceMessage:
        if not self.we_requested_it:
            raise LocalProtocolError(
                "Request was not started by us, can't start another request."
            )
        if self.state != KVFState.CREATED and self.state != KVFState.REQUESTED:
            raise LocalProtocolError(
                "Key verification request with the transaction id {transaction_id} already accepted."
            )
        if device in self.devices:
            raise LocalProtocolError(f"Already requested device {device.device_id}.")

        self.state = KVFState.REQUESTED
        self.devices.append(device)

        content = {
            "from_device": self.own_device,
            "methods": [Sas._sas_method_v1],
            "transaction_id": self.transaction_id,
            "timestamp": time_ns() // 1_000_000,
        }

        message = ToDeviceMessage(
            "m.key.verification.request",
            device.user_id,
            device.id,
            content,
        )

        return message

    def accept_verification_request(self) -> ToDeviceMessage:
        """Accept a key verification request.

        Args:
            transaction_id (str): The transaction id of the interactive key
                verification.

        Returns a ``ToDeviceMessage`` that should be sent to the homeserver.
        """
        if self.we_requested_it:
            raise LocalProtocolError(
                "Verification request was send by us, can't accept offer."
            )

        if self.state == KVFState.CANCELED:
            raise LocalProtocolError(
                "Request was canceled before receiving ready message."
            )
        if self.state != KVFState.REQUESTED:
            raise LocalProtocolError("Request already accepted.")

        other_device = self.devices[0]

        content = {
            "from_device": self.own_device,
            "methods": [Sas._sas_method_v1],
            "transaction_id": self.transaction_id,
        }

        message = ToDeviceMessage(
            "m.key.verification.ready",
            other_device.user_id,
            other_device.id,
            content,
        )

        self.state = KVFState.READY
        return message

    def verification_request_accepted(
        self, accepting_device: OlmDevice
    ) -> List[ToDeviceMessage]:
        if not self.we_requested_it:
            raise LocalProtocolError(
                f"Request was not initialized by us, but we received an unexpected ready message from device: {accepting_device.device_id}"
            )
        if self.state == KVFState.CREATED:
            raise LocalProtocolError("Cannot accept before sending a request.")
        if self.state == KVFState.CANCELED:
            raise LocalProtocolError(
                "Request was canceled before receiving ready message."
            )
        if self.state != KVFState.REQUESTED:
            raise LocalProtocolError("Request already accepted.")
        if accepting_device not in self.devices:
            raise LocalProtocolError(
                f"Received key verification ready from unknown device: {accepting_device.device_id}"
            )

        messages = []

        for device in self.devices:
            if accepting_device == device:
                continue

            messages.append(
                self._create_cancel_message(device, self._user_accepted_reason)
            )

        self.devices = [accepting_device]
        self.state = KVFState.READY

        return messages

    def _create_cancel_message(
        self, other_device: OlmDevice, reason: Tuple[str, str]
    ) -> ToDeviceMessage:
        cancel_code, cancel_reason = reason
        content = {
            "code": cancel_code,
            "reason": cancel_reason,
            "transaction_id": self.transaction_id,
        }

        message = ToDeviceMessage(
            "m.key.verification.cancel",
            other_device.user_id,
            other_device.id,
            content,
        )

        return message

    def cancel_verification(self, other_device: OlmDevice) -> List[ToDeviceMessage]:
        if self.state == KVFState.DONE:
            raise LocalProtocolError(
                "Verification already done, can't cancel it afterwards."
            )
        if self.state == KVFState.CANCELED:
            raise LocalProtocolError("Verification request already canceled.")

        self.state = KVFState.CANCELED
        messages = []
        for device in self.devices:
            messages.append(
                self._create_cancel_message(device, self._user_cancel_error)
            )

        return messages

    def process_cancellation(self) -> List[ToDeviceMessage]:
        if self.state == KVFState.CANCELED:
            raise LocalProtocolError("Key verification already canceled")
        if self.state == KVFState.DONE:
            raise LocalProtocolError("We cannot cancel finished key verifications.")
        self.state = KVFState.CANCELED
        if not self.we_requested_it:
            return []

        messages = []
        for device in self.devices:
            messages.append(
                self._create_cancel_message(device, self._user_cancel_error)
            )

        return messages

    def verification_done(self) -> ToDeviceMessage:
        """Create a content dictionary to signal the end of verification."""
        if self.state == KVFState.CANCELED:
            raise LocalProtocolError("Key verification was canceled before finished")

        if self.state == KVFState.DONE:
            raise LocalProtocolError("Key verification already finished")

        if self.state != KVFState.READY:
            raise LocalProtocolError("Key verification not finished")

        message = ToDeviceMessage(
            "m.key.verification.done",
            self.devices[0].user_id,
            self.devices[0].id,
            {
                "transaction_id": self.transaction_id,
            },
        )

        self.state = KVFState.DONE

        return message
