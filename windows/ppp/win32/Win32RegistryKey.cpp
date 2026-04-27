#include <windows/ppp/win32/Win32RegistryKey.h>
#include <ppp/diagnostics/Error.h>

namespace ppp
{
    namespace win32
    {
        // ��ȡBOOLֵ
        bool GetRegistryValueBool(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, bool* bOK) noexcept
        {
            DWORD data = GetRegistryValueDword(hKey, subKey, valueName, bOK);
            return (data != 0);
        }

        // ��ȡ�ַ���ֵ
        std::wstring GetRegistryValueString(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, bool* bOK) noexcept
        {
            LONG result;
            HKEY keyHandle;
            wchar_t buffer[MAX_PATH];
            DWORD size = MAX_PATH;
            DWORD type;

            if (NULLPTR != bOK)
            {
                *bOK = false;
            }

            result = RegOpenKeyEx(hKey, subKey.c_str(), 0, KEY_READ, &keyHandle);
            if (result != ERROR_SUCCESS)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32RegistryOpenFailed);
                return L"";
            }

            result = RegQueryValueEx(keyHandle, valueName.c_str(), 0, &type, reinterpret_cast<BYTE*>(buffer), &size);
            RegCloseKey(keyHandle);

            if (result != ERROR_SUCCESS)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32RegistryReadFailed);
                return L"";
            }
            if (type != REG_SZ)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32RegistryReadTypeMismatch);
                return L"";
            }

            if (NULLPTR != bOK)
            {
                *bOK = true;
            }

            return std::wstring(buffer, size / sizeof(wchar_t));
        }

        // ��ȡDWORDֵ
        DWORD GetRegistryValueDword(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, bool* bOK) noexcept
        {
            LONG result;
            HKEY keyHandle;
            DWORD data;
            DWORD size = sizeof(DWORD);
            DWORD type;

            if (NULLPTR != bOK)
            {
                *bOK = false;
            }

            result = RegOpenKeyEx(hKey, subKey.c_str(), 0, KEY_READ, &keyHandle);
            if (result != ERROR_SUCCESS)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32RegistryOpenFailed);
                return 0;
            }

            result = RegQueryValueEx(keyHandle, valueName.c_str(), 0, &type, reinterpret_cast<BYTE*>(&data), &size);
            RegCloseKey(keyHandle);

            if (result != ERROR_SUCCESS)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32RegistryReadFailed);
                return 0;
            }
            if (type != REG_DWORD)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32RegistryReadTypeMismatch);
                return 0;
            }

            if (NULLPTR != bOK)
            {
                *bOK = true;
            }

            return data;
        }

        // ��ȡWORD����ֵ
        ppp::vector<WORD> GetRegistryValueWordArray(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, bool* bOK) noexcept
        {
            LONG result;
            HKEY keyHandle;
            DWORD type;
            DWORD dataSize;

            if (NULLPTR != bOK)
            {
                *bOK = false;
            }

            result = RegOpenKeyEx(hKey, subKey.c_str(), 0, KEY_READ, &keyHandle);
            if (result != ERROR_SUCCESS)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32RegistryOpenFailed);
                return ppp::vector<WORD>();
            }

            result = RegQueryValueEx(keyHandle, valueName.c_str(), 0, &type, NULLPTR, &dataSize);
            if (result != ERROR_SUCCESS)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32RegistryReadFailed);
                RegCloseKey(keyHandle);
                return ppp::vector<WORD>();
            }
            if (type != REG_BINARY)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32RegistryReadTypeMismatch);
                RegCloseKey(keyHandle);
                return ppp::vector<WORD>();
            }

            ppp::vector<BYTE> dataBuffer(dataSize);
            result = RegQueryValueEx(keyHandle, valueName.c_str(), 0, &type, dataBuffer.data(), &dataSize);
            RegCloseKey(keyHandle);

            if (result != ERROR_SUCCESS)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32RegistryReadFailed);
                return ppp::vector<WORD>();
            }

            ppp::vector<WORD> dataArray(dataSize / sizeof(WORD));
            memcpy(dataArray.data(), dataBuffer.data(), dataSize);

            if (NULLPTR != bOK)
            {
                *bOK = true;
            }

            return dataArray;
        }

        // д��BOOLֵ
        bool SetRegistryValueBool(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, bool valueData) noexcept
        {
            DWORD data = valueData ? 1 : 0;
            return SetRegistryValueDword(hKey, subKey, valueName, data);
        }

        // д���ַ���ֵ
        bool SetRegistryValueString(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, const std::wstring& valueData) noexcept
        {
            LONG result;
            HKEY keyHandle;
            DWORD dwDisposition;

            result = RegCreateKeyEx(hKey, subKey.c_str(), 0, NULLPTR, 0, KEY_ALL_ACCESS, NULLPTR, &keyHandle, &dwDisposition);
            if (result != ERROR_SUCCESS)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32RegistryCreateFailed);
                return false;
            }

            result = RegSetValueEx(keyHandle, valueName.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(valueData.c_str()), static_cast<DWORD>(valueData.length() * sizeof(wchar_t)));
            RegCloseKey(keyHandle);

            if (result != ERROR_SUCCESS)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32RegistryWriteFailed);
                return false;
            }
            return true;
        }

        // д��DWORDֵ
        bool SetRegistryValueDword(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, DWORD valueData) noexcept
        {
            LONG result;
            HKEY keyHandle;
            DWORD dwDisposition;

            result = RegCreateKeyEx(hKey, subKey.c_str(), 0, NULLPTR, 0, KEY_ALL_ACCESS, NULLPTR, &keyHandle, &dwDisposition);
            if (result != ERROR_SUCCESS)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32RegistryCreateFailed);
                return false;
            }

            result = RegSetValueEx(keyHandle, valueName.c_str(), 0, REG_DWORD, reinterpret_cast<BYTE*>(&valueData), sizeof(valueData));
            RegCloseKey(keyHandle);

            if (result != ERROR_SUCCESS)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32RegistryWriteFailed);
                return false;
            }
            return true;
        }

        // д��WORD����ֵ
        bool SetRegistryValueWordArray(HKEY hKey, const std::wstring& subKey, const std::wstring& valueName, const WORD* valueData, DWORD dataSize) noexcept
        {
            LONG result;
            HKEY keyHandle;
            DWORD dwDisposition;

            result = RegCreateKeyEx(hKey, subKey.c_str(), 0, NULLPTR, 0, KEY_ALL_ACCESS, NULLPTR, &keyHandle, &dwDisposition);
            if (result != ERROR_SUCCESS)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32RegistryCreateFailed);
                return false;
            }

            result = RegSetValueEx(keyHandle, valueName.c_str(), 0, REG_BINARY, reinterpret_cast<const BYTE*>(valueData), dataSize);
            RegCloseKey(keyHandle);

            if (result != ERROR_SUCCESS)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Win32RegistryWriteFailed);
                return false;
            }
            return true;
        }
    }
}
