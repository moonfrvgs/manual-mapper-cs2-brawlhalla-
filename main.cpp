#include "main.h"
#pragma warning(push)
#pragma warning(disable : 6011)
#pragma warning(disable : 4312)
#pragma warning(disable : 6387)
#pragma warning(disable : 6031)

template<typename T = void*> requires std::is_same_v<T, void*>

class handle_hijacker {
private:
    NTSTATUS status = 0;
    CLIENT_ID client_id{};
    DWORD new_size = sizeof(SYSTEM_HANDLE_INFORMATION);
    void* handle = nullptr;
    void* hijack = nullptr;
    BOOLEAN privilege{};


    OBJECT_ATTRIBUTES initialize_object_attributes() {
        OBJECT_ATTRIBUTES obj{};
        obj.Length = sizeof(OBJECT_ATTRIBUTES);
        obj.Attributes = 0;
        obj.ObjectName = nullptr;
        obj.RootDirectory = nullptr;
        obj.SecurityDescriptor = nullptr;
        obj.SecurityQualityOfService = nullptr;
        return obj;
    }

    [[noreturn]] void exception_handler(_In_ const char* message) {
        std::cout << message << '\n';
        throw std::runtime_error(message);
    }

    bool handle_check(_In_ void* handle) {
        return handle != nullptr && handle != INVALID_HANDLE_VALUE;
    }

public:
    explicit handle_hijacker(const handle_hijacker&) = delete;

    explicit handle_hijacker(_In_ DWORD target_process_id, _In_ DWORD rights) {
        if (target_process_id == 0) {
            exception_handler("[-] invalid process id (handle hijacker class)");
        }
        std::cout << "[+] process id: [" << target_process_id << "]\n";

        auto rtl_adjust_privilege = reinterpret_cast<RtlAdjustPrivilege>(resolve_address("RtlAdjustPrivilege"));
        auto nt_query_system_information = reinterpret_cast<NtQuerySystemInformation>(resolve_address("NtQuerySystemInformation"));
        auto nt_duplicate_object = reinterpret_cast<NtDuplicateObject>(resolve_address("NtDuplicateObject"));
        auto nt_open_process = reinterpret_cast<NtOpenProcess>(resolve_address("NtOpenProcess"));
        auto nt_query_information_process = reinterpret_cast<NtQueryInformationProcess>(resolve_address("NtQueryInformationProcess"));


        if (!rtl_adjust_privilege || !nt_query_system_information || !nt_duplicate_object || !nt_open_process) {
            exception_handler("[-] failed to resolve required functions from ntdll");
        }

        OBJECT_ATTRIBUTES obj = initialize_object_attributes();
        rtl_adjust_privilege(0x14, TRUE, FALSE, &privilege);

        std::unique_ptr<std::byte[]> buffer = std::make_unique<std::byte[]>(new_size);
        auto handle_information = reinterpret_cast<psystem_handle_information>(buffer.get());

        while ((status = nt_query_system_information(16, handle_information, new_size, nullptr)) == STATUS_INFO_LENGTH_MISMATCH) {
            new_size *= 2;
            try {
                buffer = std::make_unique<std::byte[]>(new_size);
                handle_information = reinterpret_cast<psystem_handle_information>(buffer.get());
            }
            catch (const std::bad_alloc&) {
                exception_handler("[-] memory allocation failed");
            }
        }

  
        if (!NT_SUCCESS(status)) {
            exception_handler("[-] querying system handle information failed");
        }

        for (ULONG i = 0; i < handle_information->HandleCount; ++i) {
            const auto& entry = handle_information->Handles[i];


            if (entry.ObjectTypeNumber != process_handle_type)
                continue;

            client_id.UniqueProcess = reinterpret_cast<void*>(static_cast<uintptr_t>(entry.ProcessId));

            status = nt_open_process(&handle, PROCESS_DUP_HANDLE, &obj, &client_id);
            if (!NT_SUCCESS(status) || !handle_check(handle))
                continue;


            HANDLE source_handle = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(entry.Handle));
            status = nt_duplicate_object(handle, source_handle, GetCurrentProcess(), &hijack, rights, 0, 0);
            if (!NT_SUCCESS(status) || !handle_check(hijack))
                continue;

            if (get_process_id(hijack) == target_process_id) {
                std::cout << "[+] hijacked from target handle: 0x" << std::hex << entry.Handle << " now mapped in our process as: 0x" << reinterpret_cast<uintptr_t>(hijack) << "\n";
                close_handle(handle);
                handle = nullptr;
                return;
            }

            close_handle(hijack);
            hijack = nullptr;
        }

        std::cout << "[-] couldn't retrieve handle\n";
    }

    ~handle_hijacker() {
        if (handle_check(handle)) close_handle(handle);
        if (handle_check(hijack)) close_handle(hijack);
    }

    void* retrieve_handle() {
        if (!handle_check(hijack)) {
            exception_handler("[-] invalid handle: can't retrieve");
        }
        SetHandleInformation(hijack, HANDLE_FLAG_PROTECT_FROM_CLOSE, FALSE);
        return hijack;
    }
};


namespace container {
    [[noreturn]] void error_handler(_In_ std::string_view message) {
        MessageBoxA(NULL, message.data(), "Error", MB_OK);
        exit(-1);
    };

    void print(_In_ const char* message) {
        std::cout << message << std::endl;
    };
}
namespace pe {
    struct pe_headers {
        image_dos_header* dos_header = nullptr;
        image_nt_header* nt_headers = nullptr;
        image_optional_header* optional_header = nullptr;
        image_file_header* file_header = nullptr;
    };

    pe_headers resolve_pe_headers(void* image_base) {
        pe_headers pe;
        pe.dos_header = reinterpret_cast<image_dos_header*>(image_base);
        pe.nt_headers = reinterpret_cast<image_nt_header*>(reinterpret_cast<uint64_t>(image_base) + pe.dos_header->e_lfanew);
        pe.optional_header = &pe.nt_headers->OptionalHeader;
        pe.file_header = &pe.nt_headers->FileHeader;
        return pe;
    };

    bool valid_file(_In_ image_dos_header* dos_header) {
        if (dos_header->e_magic != 0x5A4D) { return false; }
        return true;
    };
};

namespace memory {
    dword get_process_id(_In_ std::string_view window_name) {
        auto window = ::find_window(null, window_name.data()); dword process_id = 0;
        if (!::get_window_thread_process_id(window, &process_id)) {
            std::cout << "[-] error returning process id\n";
        };
        return process_id;
    };


    uintptr_t get_module_base_address(_In_ const char* module_name, _In_ dword process_id) {

        uintptr_t base_address = 0;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);

        if (snapshot != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 me32;
            me32.dwSize = sizeof(me32);

            if (Module32First(snapshot, &me32)) {
                do {
                    if (_stricmp(me32.szModule, module_name) == 0) {
                        base_address = (uintptr_t)me32.modBaseAddr;
                        break;
                    }
                } while (Module32Next(snapshot, &me32));
            }
            CloseHandle(snapshot);
        }
        return base_address;
    }

    ULONGLONG  retrieve_thread_start_time(_In_ void* thread_handle) {
        FILETIME creation, exit, kernel, user;
        if (GetThreadTimes(thread_handle, &creation, &exit, &kernel, &user)) {
            ULARGE_INTEGER time;
            time.LowPart = creation.dwLowDateTime;
            time.HighPart = creation.dwHighDateTime;
            return time.QuadPart;
        }
        else {
            container::error_handler("[-] couldn't retrieve thread time");
            return 0;
        }
    };


    dword retrieve_main_thread_id(_In_ dword process_identifier) {
        THREADENTRY32 thread_entry32{ thread_entry32.dwSize = sizeof(THREADENTRY32) };
        void* thread_handle_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

        if (!thread_handle_snapshot || thread_handle_snapshot == INVALID_HANDLE_VALUE) {
            container::error_handler("[-] error couldn't retrieve thread snapshot");
        }


        ULONGLONG lowest_time = ~0ULL;  DWORD main_thread_id = { 0 };

        if (!Thread32First(thread_handle_snapshot, &thread_entry32)) {
            CloseHandle(thread_handle_snapshot);
            return 0;
        }

        if (thread_handle_snapshot == INVALID_HANDLE_VALUE) {
            container::error_handler("[-] error couldn't retrieve thread snapshot");
            return 0;
        }

        do {

            if (thread_entry32.th32OwnerProcessID == process_identifier) {
                void* thread_handle = OpenThread(THREAD_QUERY_INFORMATION, FALSE, thread_entry32.th32ThreadID);
                if (thread_handle) {
                    ULONGLONG start_time = memory::retrieve_thread_start_time(thread_handle);
                    if (start_time != 0 && start_time < lowest_time) {
                        lowest_time = start_time;
                        main_thread_id = thread_entry32.th32ThreadID;
                        std::cout << "[+] main thread id: [" << main_thread_id << "]\n";
                    }
                    CloseHandle(thread_handle);
                }
            }


        } while (Thread32Next(thread_handle_snapshot, &thread_entry32));
        CloseHandle(thread_handle_snapshot);
        return main_thread_id;
    };

}



bool manual_map(_In_ std::string_view process_window_name, _In_ const char* dll_path) {
    ntstatus status = 0;
    handle_hijacker<void*> hijack(memory::get_process_id(process_window_name.data()), PROCESS_ALL_ACCESS);
    std::fstream file(dll_path, std::ios::in | std::ios::binary | std::ios::ate);
    if (file.fail()) {
        container::error_handler("[-] Error opening dll");
    }
    std::cout << "[+] opening dll\n";

    std::streamsize dll_size = file.tellg();
    std::unique_ptr<std::byte[]> dll_data = std::make_unique<std::byte[]>(dll_size);
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(dll_data.get()), dll_size);

    if (!file) {
        container::error_handler("[-] Error reading dll");
    }
    file.close();
    std::cout << "[+] read dll bytes\n";
    auto allocate_external_memory = [](_In_ void* permissions, _In_ dword access_mask, _In_ size_t allocated_size, _In_ void* preferred_address) -> void* {
        void* memory_allocation = ::VirtualAllocEx(permissions, preferred_address, allocated_size, MEM_COMMIT | MEM_RESERVE, access_mask);
        if (!memory_allocation) {
            memory_allocation = ::VirtualAllocEx(permissions, nullptr, allocated_size, MEM_COMMIT | MEM_RESERVE, access_mask);
            if (!memory_allocation) {
                container::error_handler("[-] error allocating memory");
            }
        }
        return memory_allocation;
    };


    hmodule dll_module = LoadLibraryEx(dll_path, nullptr, DONT_RESOLVE_DLL_REFERENCES);
    pe::pe_headers pe_headers = pe::resolve_pe_headers(dll_module);
    void* allocation = allocate_external_memory(hijack.retrieve_handle(), PAGE_EXECUTE_READWRITE, pe_headers.optional_header->SizeOfImage, (void*)pe_headers.optional_header->ImageBase);

    if (!WriteProcessMemory(hijack.retrieve_handle(), allocation, dll_module, pe_headers.optional_header->SizeOfHeaders, nullptr)) {
        container::error_handler("[-] error couldn't write headers");
    }


    auto nt_write_virtual_memory = reinterpret_cast<decltype(&NtWriteVirtualMemory)>(GetProcAddress(GetModuleHandle("ntdll.dll"), "NtWriteVirtualMemory"));
    const unsigned char* file_base = reinterpret_cast<const unsigned char*>(dll_data.get());
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(const_cast<unsigned char*>(file_base));
    IMAGE_NT_HEADERS64* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(const_cast<unsigned char*>(file_base + dos->e_lfanew));
    IMAGE_OPTIONAL_HEADER* opt_header = &nt->OptionalHeader;

    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        container::error_handler("[-] invalid pe type");
    }

    size_t size_of_image = nt->OptionalHeader.SizeOfImage;
    size_t size_of_headers = nt->OptionalHeader.SizeOfHeaders;
    uintptr_t image_base_preferred = nt->OptionalHeader.ImageBase;
    uintptr_t delta = (uintptr_t)allocation - image_base_preferred;


    if (!WriteProcessMemory(hijack.retrieve_handle(), allocation, dll_data.get(), size_of_headers, nullptr)) {
        container::error_handler("[-] couldn't write headers");
    }

    IMAGE_SECTION_HEADER* section_header = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section_header) {
        if (section_header->SizeOfRawData == 0) continue;

        NTSTATUS status = nt_write_virtual_memory(hijack.retrieve_handle(), reinterpret_cast<void*>((uintptr_t)allocation + section_header->VirtualAddress), dll_data.get() + section_header->PointerToRawData, section_header->SizeOfRawData, nullptr);
        if (!NT_SUCCESS(status)) {
            container::error_handler("[-] failed writing section");
        }

        std::cout << "[+] " << section_header->Name << " patched\n";
    }

    auto& reloc_dir = nt->OptionalHeader.DataDirectory[5];
    if (reloc_dir.VirtualAddress != 0 && reloc_dir.Size != 0) {
        const unsigned char* reloc_base = (byte*)dll_module + reloc_dir.VirtualAddress;
        const unsigned char* reloc_end = reloc_base + reloc_dir.Size;
        const IMAGE_BASE_RELOCATION* pblock = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(reloc_base);

        while (reinterpret_cast<const unsigned char*>(pblock) < reloc_end && pblock->SizeOfBlock) {
            size_t entry_count = (pblock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            const WORD* entries = reinterpret_cast<const WORD*>(pblock + 1);
            uintptr_t page_rva = pblock->VirtualAddress;

            for (size_t i = 0; i < entry_count; ++i) {
                WORD type = entries[i] >> 12;
                WORD offset = entries[i] & 0x0FFF;

                if (type == IMAGE_REL_BASED_DIR64) {
                    uintptr_t target_rva = page_rva + offset;
                    uintptr_t absolute_address = (uintptr_t)allocation + target_rva;

                    uint64_t original_value = 0;
                    if (target_rva + sizeof(uint64_t) <= size_of_image) {
                        original_value = *reinterpret_cast<const uint64_t*>(file_base + target_rva);
                    }

                    uint64_t patched = original_value + (uint64_t)delta;

                    NTSTATUS st = nt_write_virtual_memory(hijack.retrieve_handle(), reinterpret_cast<void*>(absolute_address), &patched, sizeof(patched), nullptr);

                    if (!NT_SUCCESS(st)) {
                        container::error_handler("[-] failed writing relocation patch");
                    }
                }
            }
            pblock = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(reinterpret_cast<const unsigned char*>(pblock) + pblock->SizeOfBlock);
        }

		std::cout << "[+] relocations patched\n"; 

    }
    

    auto load_dll = [&](std::string& dll_name) -> void {
        void* remote_buffer = VirtualAllocEx(hijack.retrieve_handle(), nullptr, 0x1000, MEM_COMMIT, PAGE_READWRITE);
        if (!remote_buffer) {
            container::error_handler("[-] couldn't allocate memory for dll name");
        }
        WriteProcessMemory(hijack.retrieve_handle(), remote_buffer, dll_name.c_str(), dll_name.size(), nullptr);
        void* hthread = CreateRemoteThread(hijack.retrieve_handle(), nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA")), remote_buffer, 0, nullptr);

        if (!hthread) {
            container::error_handler("[-] couldn't create remote thread for dll injection");
        }
        WaitForSingleObject(hthread, INFINITE);
        std::cout << "[+] injected: " << dll_name << "\n";
        VirtualFreeEx(hijack.retrieve_handle(), remote_buffer, 0, MEM_RELEASE);
        CloseHandle(hthread);
     };

    auto string_conversion = [&](void* address) -> std::string {
        std::string name = "";
        char character = 0;
		size_t offset = 0;

        while (true) {
            if(!ReadProcessMemory(hijack.retrieve_handle(), (void*)((byte*)address + offset), &character, sizeof(char), nullptr)) {
                container::error_handler("[-] couldn't read imported dll name");
			}

            if (character == '\0')
                break;

            name.push_back(character);
            offset++;
        }
        
        return name;
    };
    

	auto import_directory = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(!import_directory->VirtualAddress || !import_directory->Size) {
        container::error_handler("[-] no import directory found");
	}

	auto remote_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)((byte*)allocation + import_directory->VirtualAddress);
    IMAGE_IMPORT_DESCRIPTOR local_descriptor {};
    if (!::ReadProcessMemory(hijack.retrieve_handle(), remote_descriptor, &local_descriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), nullptr)) {
		container::error_handler("[-] couldn't read import descriptor");
    }

    while (local_descriptor.Name) {
		std::string dll_name = string_conversion((void*)((byte*)allocation + local_descriptor.Name)); load_dll(dll_name); 
        uintptr_t original_first_thunk = (uintptr_t)allocation + local_descriptor.OriginalFirstThunk;
		uintptr_t first_thunk = (uintptr_t)allocation + local_descriptor.FirstThunk;

		IMAGE_THUNK_DATA64 thunk_data{};
        if (!::ReadProcessMemory(hijack.retrieve_handle(), (void*)original_first_thunk, &thunk_data, sizeof(IMAGE_THUNK_DATA64), nullptr)) {
			container::error_handler("[-] couldn't read thunk data");
        }

        while (thunk_data.u1.AddressOfData) {
            uintptr_t function_adddress = 0;
            if (IMAGE_SNAP_BY_ORDINAL(thunk_data.u1.Ordinal))
            {
				function_adddress = (uintptr_t)GetProcAddress(LoadLibraryA(dll_name.c_str()), (LPCSTR)(thunk_data.u1.Ordinal & 0xFFFF));
            }
            else {
				auto import_by_name = (IMAGE_IMPORT_BY_NAME*)((byte*)allocation + thunk_data.u1.AddressOfData);
                char buffer[256]; 
                if (!::ReadProcessMemory(hijack.retrieve_handle(), import_by_name, &buffer, sizeof(buffer), nullptr)) {
					std::cout << "[-] couldn't read import by name\n";
                }
				function_adddress = (uintptr_t)GetProcAddress(LoadLibraryA(dll_name.c_str()), ((IMAGE_IMPORT_BY_NAME*)buffer)->Name);
            }
            if (!::WriteProcessMemory(hijack.retrieve_handle(), (void*)first_thunk, &function_adddress, sizeof(uintptr_t), nullptr)) {
				std::cout << "[-] couldn't write function address\n";
            }
			original_first_thunk += sizeof(IMAGE_THUNK_DATA64);
            first_thunk += sizeof(IMAGE_THUNK_DATA64);

            if (!::ReadProcessMemory(hijack.retrieve_handle(), (void*)original_first_thunk, &thunk_data, sizeof(IMAGE_THUNK_DATA64), nullptr)) {
				container::error_handler("[-] couldn't read thunk data");
            }
        }
		remote_descriptor++;
        if (!::ReadProcessMemory(hijack.retrieve_handle(), remote_descriptor, &local_descriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), nullptr)) {
			container::error_handler("[-] couldn't read import descriptor");
        }
    }
    
   
	std::cout << "[+] launching dll entry point\n";
    struct dll_stub {
        BYTE code[64];
    };

    dll_stub stub = {
        {
            0x48, 0x83, 0xEC, 0x28,              
            0x48, 0xB9,                    
            0,0,0,0,0,0,0,0,
            0xBA, 0x01, 0x00, 0x00, 0x00,
            0x4D, 0x31, 0xC0,               
            0x48, 0xB8,                                  
            0,0,0,0,0,0,0,0,
            0xFF, 0xD0,                             
            0x48, 0x83, 0xC4, 0x28,                       
            0xC3                               
        }
    };
    *(uintptr_t*)(stub.code + 6) = (uintptr_t)allocation; 
    *(uintptr_t*)(stub.code + 24) = (uintptr_t)allocation + opt_header->AddressOfEntryPoint;

    void* remote_stub = VirtualAllocEx(hijack.retrieve_handle(),nullptr,sizeof(stub),MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!::WriteProcessMemory(hijack.retrieve_handle(), remote_stub, &stub, sizeof(stub), nullptr)) {
		container::error_handler("[-] couldn't write remote stub");
    }



    HANDLE thread = CreateRemoteThread(hijack.retrieve_handle(), nullptr, 0, (LPTHREAD_START_ROUTINE)remote_stub, nullptr, 0, nullptr);
    if(!thread) {
        container::error_handler("[-] couldn't create remote thread for dll entry point");
	}
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);

    return true;
}

int main() {
    bool manual_mapper = manual_map("Brawlhalla", "C:\\Users\\cex\\source\\repos\\radical injector\\x64\\Release\\Dll1.dll");

}


