import pefile
import os

if __name__ == "__main__":
    filename = input("Введите путь к исполняемому файлу без кавычек: ")

    try:
        pe = pefile.PE(filename)
        print("DOS Header:")
        print(f"  Magic: {hex(pe.DOS_HEADER.e_magic)}")
        print(f"  Bytes on Last Page of File: {pe.DOS_HEADER.e_cblp}")
        print("\nFile Header:")
        print(f"  Machine: {hex(pe.FILE_HEADER.Machine)}")
        print(f"  Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
        print("\nOptional Header:")
        print(f"  Magic: {hex(pe.OPTIONAL_HEADER.Magic)}")
        print(f"  Address of Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        print("\nSection Headers:")
        for section in pe.sections:
            print(f"  Name: {section.Name.decode('utf-8')}")
            print(f"    Virtual Address: {hex(section.VirtualAddress)}")
            print(f"    Size of Raw Data: {section.SizeOfRawData}")
        print("\nImport Table:")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"  DLL Name: {entry.dll.decode('utf-8')}")
            for func in entry.imports:
                print(f"    Function Name: {func.name.decode('utf-8') if func.name else ''}")
    except Exception as e:
        print(f"Ошибка: {str(e)}")

    os.system("pause")
    
