#pragma once

/* STORED DEFAULT DRIVER SYSTEM BECAUSE I DON'T SEE THE POINT OF CHANGING IT. */

bool start_driver()
{
	/* Handle Driver */
	driver().handle_driver();

	/* If driver is not loaded then */
	if (!driver().is_loaded())
	{
		cout << xor_a("[+] Initializing drivers . . .") << endl;
		if (!map_driver())
		{
			cout << xor_a("[-] Driver mapper launch failed.") << endl;
			return false;
		}
	}

	driver().handle_driver();
	const bool loaded = driver().is_loaded();
	loaded ? cout << xor_a("driver initialized!") << endl : cout << xor_a("driver initialize error =<") << endl;
	return loaded;
}

