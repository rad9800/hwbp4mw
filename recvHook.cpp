HWBP recv_hook{ (uintptr_t)GetProcAddress((LoadLibrary(L"WS2_32.dll"),
	GetModuleHandle(L"WS2_32.dll")),"recv"), 3,
	([&](PEXCEPTION_POINTERS ExceptionInfo) {
		
		for (auto& i : ADDRESS_MAP) {
			if (i.first == ExceptionInfo->ContextRecord->Rip) {
				SetHWBP(GetCurrentThread(), i.first, i.second.pos, false);
			}
		}

		char verbuf[9]{ 0 };
		int	verbuflen{ 9 }, recvlen{ 0 };

		recvlen = recv(ExceptionInfo->ContextRecord->Rcx, verbuf,
				   verbuflen, MSG_PEEK);

		BYTE TLS[] = { 0x17, 0x03, 0x03 };

		if (recvlen >= 3) {
			if ((memcmp(verbuf, TLS, 3) == 0))1
			{
				MSG_AUTH msg{ 0 };
				// We'll peek like SockDetour as to not eat the message
				recvlen = recv(ExceptionInfo->ContextRecord->Rcx, (char*)&msg,
					sizeof(MSG_AUTH), MSG_PEEK);
					// Authenticate and proceed

			}
		}

		// Set corresponding Dr
		for (auto& i : ADDRESS_MAP) {
			if (i.first == ExceptionInfo->ContextRecord->Rip) {
				SetHWBP(GetCurrentThread(), i.first, i.second.pos, true);
			}
		}

		ExceptionInfo->ContextRecord->EFlags |= (1 << 16);
}) };
