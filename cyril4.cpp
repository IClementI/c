//Ce programme effectue plusieurs operations sur les cles de registre et les repertoires dans un environnement Windows

#pragma comment(lib, "advapi32.lib")    
#include <filesystem>                   
#include <iostream>                     
#include <windows.h>                    
#include <stdio.h>                      
#include <aclapi.h>                     
#include <direct.h>                     
#include <tchar.h>                  
#include <sddl.h>             

//La fonction "AddFullControlToEveryone" a pour objectif d'ajouter des permissions (controle total) ainsi que le groupe "Everyone" (Tout le monde ) a un dossier specifie en parametre de la fonction
void AddFullControlToEveryone(LPCSTR folderPath) {
    PSID pEveryoneSID = NULL;                                                                                          
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;                                               
    if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSID)) {          
        std::cerr << "Erreur allocation SID: " << GetLastError() << std::endl;                             
        return;                               
    }

    //Initialise une structure EXPLICIT_ACCESS pour un ACE (entree de controle d'acces )
    EXPLICIT_ACCESS ea;                                                
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));                           
    ea.grfAccessPermissions = GENERIC_ALL;                               
    ea.grfAccessMode = SET_ACCESS;                                     
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;             
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;                            
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;              
    ea.Trustee.ptstrName = (LPTSTR)pEveryoneSID;                        

    //Creer une nouvelle ACL (Access Control List) qui contient la nouvelle ACE
    PACL pACL = NULL;                                                                  
    DWORD dwRes = SetEntriesInAcl(1, &ea, NULL, &pACL);                                
    if (ERROR_SUCCESS != dwRes) {                                                     
        std::cerr << "Erreur d'etablissement des entrees dans ACL : " << dwRes << std::endl;   
        if (pEveryoneSID) FreeSid(pEveryoneSID);
        if (pACL) LocalFree(pACL);                              
        return;                                                                    
    }
    //Applique l'ACL comme DACL de l'objet
    dwRes = SetNamedSecurityInfoA((LPSTR)folderPath, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pACL, NULL); 
    if (ERROR_SUCCESS != dwRes) {                                                           
        std::cerr << "Erreur de definition du nom des infos de securite :  " << dwRes << std::endl;    
    } else {
        std::cout <<  "Le controle total a ete ajoute au Groupe Everyone " << std::endl;      
    }

    if (pACL) LocalFree(pACL);                          
    if (pEveryoneSID) FreeSid(pEveryoneSID);   
}

//Fonction pour ajouter le groupe "Everyone" ainsi que le control total a une cle du registre HKEY_CUURENT_USER
void AddEveryoneFullControlToRegistryKey(HKEY hKeyRoot, LPCTSTR subKey) {
    HKEY hKey;                      
    LONG lResult = RegOpenKeyEx(hKeyRoot, subKey, 0, WRITE_DAC | KEY_READ, &hKey);  
    if (lResult != ERROR_SUCCESS) {             
        std::cerr << "Erreur d'ouverture de la cle de registre: " << lResult << std::endl;
        RegCloseKey(hKey); 
        return;                                                    
    }

    // Creer un descripteur de securite avec contrôle total pour "Everyone"
    PSECURITY_DESCRIPTOR pSD = NULL;                            
    const TCHAR *szSDDL = _T("D:P(A;OICI;GA;;;WD)");            

    // Convertit la chaîne SDDL en un descripteur de securite
    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(szSDDL, SDDL_REVISION_1, &pSD, NULL)) {           
        std::cerr << "Erreur de conversion de la chaîne SDDL en descripteur de securite." << std::endl;
        LocalFree(pSD); 
        RegCloseKey(hKey);                        
        return;                                     
    }

     // Initialise les variables pour la DACL, la presence de la DACL et son etat par defaut
    PACL pDACL = NULL;
    BOOL bDaclPresent = FALSE;
    BOOL bDaclDefaulted = FALSE;
    if (!GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDACL, &bDaclDefaulted)) {    
        std::cerr << "Erreur lors de l'extraction de la DACL du descripteur de securite." << std::endl;
        LocalFree(pSD);                       
        RegCloseKey(hKey);                    
        return;                               
    }

    // Definit la nouvelle DACL sur la cle de registre
    lResult = SetSecurityInfo(hKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, pDACL, NULL);           
    if (lResult != ERROR_SUCCESS) {                                                                               
        std::cerr << "Erreur de definition de la nouvelle DACL: " << lResult << std::endl;                        
    } else {
        std::cout << "Permissions modifiees avec succes." << std::endl;                    
    }


    LocalFree(pSD);                         
    RegCloseKey(hKey);
    return;                      
}


//Les fonctions pour activer certains privileges specifiques ne concerne que le registre HKEY_LOCAL_MACHINE
//Fonction pour activer un privilege specifique
BOOL EnablePrivilege(LPCTSTR privilege) {
    HANDLE token;                   
    TOKEN_PRIVILEGES tp;           
    BOOL result = FALSE;            
    //essaye d'ouvrir le jeton pour ajouter le privilege voulu
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {   
        if (LookupPrivilegeValue(NULL, privilege, &tp.Privileges[0].Luid)) {                    
            tp.PrivilegeCount = 1;                                                               
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;                                  

            result = AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, 0);                       
        } else {                                                                                 
            std::cerr << "Echec de la recherche de la valeur du privilege : " << GetLastError() << std::endl;
        }
        CloseHandle(token);                                                            
    } else {                                                                          
        std::cerr << "Echec de l'ouverture du jeton de processus: " << GetLastError() << std::endl;
    }

    return (result && GetLastError() == ERROR_SUCCESS);             
}

// Fonction pour prendre possession d'une cle de registre. Prend deux arguments :hKeyRoot (handle de la cle de registre racine) et subKey (chemin de la sous-cle dont on veut prendre possession)
BOOL TakeOwnership(HKEY hKeyRoot, LPCTSTR subKey) {
        //verifie si le privilege voulu est present
    if (!EnablePrivilege(SE_TAKE_OWNERSHIP_NAME)) {                                                      
        std::cerr << "Impossible d'activer le privilege SE_TAKE_OWNERSHIP_NAME." << std::endl;         
        return FALSE;                                                                                 
    }

    HKEY hKey;
    LONG lResult = RegOpenKeyEx(hKeyRoot, subKey, 0, WRITE_OWNER | READ_CONTROL, &hKey);   
                                                                                        
                                                                                           
       if (lResult != ERROR_SUCCESS) {
        lResult = RegCreateKeyEx(hKeyRoot, subKey, 0, NULL, REG_OPTION_NON_VOLATILE, WRITE_OWNER | READ_CONTROL, NULL, &hKey, NULL);
        if (lResult != ERROR_SUCCESS) {
            std::cerr << "Erreur de creation de la cle de registre: " << lResult << std::endl;
            return FALSE;                                                                     
        }
    }
    // Initialise l'autorite du SID (Security Identifier) pour les administrateurs
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;     
    PSID pAdminSID = NULL;
    if (!AllocateAndInitializeSid(&SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminSID)) {  
        std::cerr << "Erreur d'initialisation du SID Administrateurs." << std::endl;                                                     
        RegCloseKey(hKey);                                                                                                              
        return FALSE;                                                                                                                   
    }
    //Allocation de memoire pour descripteur de securite
    PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);  
    if (pSD == NULL) {                                                                                      
        std::cerr << "Erreur d'allocation pour le descripteur de securite." << std::endl;                   
        FreeSid(pAdminSID);                                                                                 
        RegCloseKey(hKey);                                                                               
        return FALSE;                                                                                      
    }
    // Initialise le descripteur de securite
    if (!InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) {                                
        std::cerr << "Erreur d'initialisation du descripteur de securite." << std::endl;                    
        LocalFree(pSD);                                                                                     
        FreeSid(pAdminSID);                                                                            
        RegCloseKey(hKey);                                                                         
        return FALSE;                                                                                      
    }

    if (!SetSecurityDescriptorOwner(pSD, pAdminSID, FALSE)) {                                               
        std::cerr << "Erreur de definition du proprietaire du descripteur de securite." << std::endl;     
        LocalFree(pSD);                                                                                   
        FreeSid(pAdminSID);                                                                              
        RegCloseKey(hKey);                                                                                
        return FALSE;                                                                                  
    }
    // Applique le descripteur de securite a la cle de registre pour en prendre possession
    lResult = SetSecurityInfo(hKey, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION, pAdminSID, NULL, NULL, NULL);   
    if (lResult != ERROR_SUCCESS) {                                                                        
        std::cerr << "Erreur de prise de possession de la cle de registre: " << lResult << std::endl;           
        LocalFree(pSD);                                                                                          
        FreeSid(pAdminSID);                                                                                    
        RegCloseKey(hKey);                                                                                      
        return FALSE;                                                                                            
    }

    LocalFree(pSD);                     
    FreeSid(pAdminSID);                 
    RegCloseKey(hKey);                  
    return TRUE;                       
}
// Fonction pour ajuster les permissions d'une cle de registre prend deux arguments : hKeyRoot(handle de la cle de registre racine) et subKey (chemin de la sous-cle dont on veut ajuster les permissions)
BOOL AdjustPermissions(HKEY hKeyRoot, LPCTSTR subKey) {    
    HKEY hKey;
    LONG lResult = RegOpenKeyEx(hKeyRoot, subKey, 0, WRITE_DAC | READ_CONTROL, &hKey);         
                                                                                               
                                                                                        
    if (lResult != ERROR_SUCCESS) {                                                            
        std::cerr << "Erreur d'ouverture de la cle de registre pour ajustement des permissions: " << lResult << std::endl;     
        return FALSE;                                                                                                      
    }
    // Initialise une chaîne SDDL (Security Descriptor Definition Language) pour definir les nouvelles permissions
    PSECURITY_DESCRIPTOR pSD = NULL;
    const TCHAR *szSDDL = _T("D:P(A;OICI;GA;;;WD)");                        

    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(szSDDL, SDDL_REVISION_1, &pSD, NULL)) {           
        std::cerr << "Erreur de conversion de la chaîne SDDL en descripteur de securite." << std::endl;         
        RegCloseKey(hKey);                                                                                     
        return FALSE;                                                                                           
    }

    PACL pDACL = NULL;
    BOOL bDaclPresent = FALSE;
    BOOL bDaclDefaulted = FALSE;
     // Extrait la DACL (Discretionary Access Control List) du descripteur de securite
    if (!GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pDACL, &bDaclDefaulted)) {                               
        std::cerr << "Erreur lors de l'extraction de la DACL du descripteur de securite." << std::endl;        
        LocalFree(pSD);                                                                                       
        RegCloseKey(hKey);                                                                               
        return FALSE;                                                                                  
    }
    // Applique la DACL a la cle de registre pour ajuster les permissions
    lResult = SetSecurityInfo(hKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, pDACL, NULL);           
    if (lResult != ERROR_SUCCESS) {                                                                               
        std::cerr << "Erreur de definition de la nouvelle DACL: " << lResult << std::endl;                         
    } else {
        std::cout << "Permissions modifiees avec succes." << std::endl;                                    
    }

    LocalFree(pSD);                                        
    RegCloseKey(hKey);                                   
    return (lResult == ERROR_SUCCESS);                
}
// Fonction pour ajouter le contrôle total pour tout le monde a une cle de registre prend deux arguments : hKeyRoot(handle de la cle de registre racine) et subKey (chemin de la sous-cle dont on veut ajuster les permissions)
void AddEveryoneFullControlToRegistryKey2(HKEY hKeyRoot, LPCTSTR subKey) {  
    if (!TakeOwnership(hKeyRoot, subKey)) {                                                  
        std::cerr << "Erreur lors de la prise de possession de la cle." << std::endl;       
        return;                                                                             
    }


    HKEY hKey;
    DWORD dwDisposition;

    LONG lResult = RegCreateKeyEx(hKeyRoot, subKey, 0, NULL, REG_OPTION_NON_VOLATILE, 
                                  WRITE_OWNER | READ_CONTROL | KEY_WOW64_64KEY, NULL, &hKey, &dwDisposition);
                                                                                                                                                 
                                                                                                                                                   
    if (lResult != ERROR_SUCCESS) {                                                                             
        std::cerr << "Erreur de creation ou d'ouverture de la cle de registre: " << lResult << std::endl;      
        return;                                                                                                
    }
    RegCloseKey(hKey);                                                                                          

    if (!AdjustPermissions(hKeyRoot, subKey)) {                                                 
        std::cerr << "Erreur lors de l'ajustement des permissions." << std::endl;               
        return;                                                                                
    }
}
//Creation des differentes cles pour registre de l'utilisateur si pas deja presente

void creation_cle(LPCSTR key) {
    HKEY hKey1;
    LONG result;
    DWORD disposition; // Variable to hold the disposition value

    result = RegCreateKeyEx(
        HKEY_CURRENT_USER,  
        key,               
        0,                 
        NULL,               
        REG_OPTION_NON_VOLATILE, 
        KEY_WRITE,          
        NULL,               
        &hKey1,            
        &disposition        // Pointer to the disposition value
    );

    if (result == ERROR_SUCCESS) {
        if (disposition == REG_CREATED_NEW_KEY) {
            std::cout << "The registry key '" << key << "' was created." << std::endl;
        } else if (disposition == REG_OPENED_EXISTING_KEY) {
            std::cout << "The registry key '" << key << "' already existed and was opened." << std::endl;
        }
        RegCloseKey(hKey1);
    } else {
        // Handle error
        DWORD errorCode = GetLastError();
        LPVOID errorMessage;

        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&errorMessage,
            0,
            NULL
        );

        std::cerr << "Failed to create or open the registry key '" << key << "'. Error code: " << errorCode << ". Message: " << (LPSTR)errorMessage << std::endl;

        LocalFree(errorMessage);
    }
}


BOOL DisableInheritanceAndReplaceChildPermissions(HKEY hKeyRoot, LPCTSTR subKey) {
    HKEY hKey;
    LONG lResult = RegOpenKeyEx(hKeyRoot, subKey, 0, WRITE_DAC | WRITE_OWNER | READ_CONTROL, &hKey);
    if (lResult != ERROR_SUCCESS) {
        std::cerr << "Erreur d'ouverture de la cle de registre : " << lResult << std::endl;
        return FALSE;
    }

    BOOL bSuccess = FALSE;
    PSECURITY_DESCRIPTOR pSD = NULL;
    PSECURITY_DESCRIPTOR pNewSD = NULL;
    PACL pDACL = NULL;
    PSID pEveryoneSID = NULL;
    PSID pAdminSID = NULL;

    do {
        // Obtenir le descripteur de securite actuel
        DWORD dwSize = 0;
        lResult = RegGetKeySecurity(hKey, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, NULL, &dwSize);
        if (lResult != ERROR_INSUFFICIENT_BUFFER) {
            std::cerr << "Erreur d'obtention de la taille du descripteur de securite : " << lResult << std::endl;
            break;
        }

        pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwSize);
        if (!pSD) {
            std::cerr << "Erreur d'allocation de memoire pour le descripteur de securite" << std::endl;
            break;
        }

        lResult = RegGetKeySecurity(hKey, DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, pSD, &dwSize);
        if (lResult != ERROR_SUCCESS) {
            std::cerr << "Erreur d'obtention du descripteur de securite : " << lResult << std::endl;
            break;
        }

        // Creer les SID pour "Everyone" et "Administrators"
        SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
        SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
        if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSID) ||
            !AllocateAndInitializeSid(&SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminSID)) {
            std::cerr << "Erreur de creation des SID : " << GetLastError() << std::endl;
            break;
        }

        // Creer une nouvelle DACL
        EXPLICIT_ACCESS ea[2];
        ZeroMemory(&ea, 2 * sizeof(EXPLICIT_ACCESS));

        ea[0].grfAccessPermissions = KEY_ALL_ACCESS;
        ea[0].grfAccessMode = SET_ACCESS;
        ea[0].grfInheritance = NO_INHERITANCE;
        ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        ea[0].Trustee.ptstrName = (LPTSTR)pEveryoneSID;

        ea[1].grfAccessPermissions = KEY_ALL_ACCESS;
        ea[1].grfAccessMode = SET_ACCESS;
        ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
        ea[1].Trustee.ptstrName = (LPTSTR)pAdminSID;

        lResult = SetEntriesInAcl(2, ea, NULL, &pDACL);
        if (lResult != ERROR_SUCCESS) {
            std::cerr << "Erreur de creation de la nouvelle DACL : " << lResult << std::endl;
            break;
        }

        // Creer un nouveau descripteur de securite
        pNewSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
        if (!pNewSD || !InitializeSecurityDescriptor(pNewSD, SECURITY_DESCRIPTOR_REVISION)) {
            std::cerr << "Erreur d'initialisation du nouveau descripteur de securite : " << GetLastError() << std::endl;
            break;
        }

        // Definir la nouvelle DACL dans le nouveau descripteur de securite
        if (!SetSecurityDescriptorDacl(pNewSD, TRUE, pDACL, FALSE)) {
            std::cerr << "Erreur de definition de la DACL sur le descripteur de securite : " << GetLastError() << std::endl;
            break;
        }

        // Appliquer le nouveau descripteur de securite a la cle de registre
        lResult = RegSetKeySecurity(hKey, DACL_SECURITY_INFORMATION, pNewSD);
        if (lResult != ERROR_SUCCESS) {
            std::cerr << "Erreur de definition de la nouvelle securite : " << lResult << std::endl;
            break;
        }

        std::cout << "L'heritage a ete desactive avec succes et les permissions des enfants ont ete remplacees." << std::endl;
        bSuccess = TRUE;

    } while (0);

    // Nettoyage
    if (pDACL) LocalFree(pDACL);
    if (pSD) LocalFree(pSD);
    if (pNewSD) LocalFree(pNewSD);
    if (pEveryoneSID) FreeSid(pEveryoneSID);
    if (pAdminSID) FreeSid(pAdminSID);
    RegCloseKey(hKey);

    return bSuccess;
}

//Creation des differents dossiers
void creation_dossier(void) {
    if (_mkdir("C:\\CLE") == 0) {
        std::cout << "Le dossier C:\\CLE a ete cree avec succes." << std::endl;
    } else {
        if (errno == EEXIST) {
            std::cout << "Le dossier C:\\CLE existe deja." << std::endl;
        } else {
            std::cerr << "Erreur lors de la creation du dossier C:\\CLE." << std::endl;
        }
    }

    if (_mkdir("C:\\CLE\\BDE") == 0) {
        std::cout << "Le dossier C:\\CLE\\BDE a ete cree avec succes." << std::endl;
    } else {
        if (errno == EEXIST) {
            std::cout << "Le dossier C:\\CLE\\BDE existe deja." << std::endl;
        } else {
            std::cerr << "Erreur lors de la creation du dossier C:\\CLE\\BDE." << std::endl;
        }
    }
}

BOOL AddLanmanWorkstationParameters() {
    HKEY hKey;
    LONG lResult;
    DWORD dwValue = 0;
    DWORD dwDisposition;

    // Open or create the key
    lResult = RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\services\\LanmanWorkstation\\Parameters",
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE | KEY_WOW64_64KEY,  // Ensure we're writing to the 64-bit view
        NULL,
        &hKey,
        &dwDisposition
    );

    if (lResult != ERROR_SUCCESS) {
        std::cerr << "Error opening or creating registry key: " << lResult << std::endl;
        return FALSE;
    }

    if (dwDisposition == REG_OPENED_EXISTING_KEY) {
        std::cout << "Existing LanmanWorkstation\\Parameters key opened." << std::endl;
    } else {
        std::cout << "New LanmanWorkstation\\Parameters key created." << std::endl;
    }

    // Set FileInfoCacheLifetime
    lResult = RegSetValueEx(hKey, "FileInfoCacheLifetime", 0, REG_DWORD, (const BYTE*)&dwValue, sizeof(dwValue));
    if (lResult != ERROR_SUCCESS) {
        std::cerr << "Error setting FileInfoCacheLifetime: " << lResult << std::endl;
        RegCloseKey(hKey);
        return FALSE;
    }
    std::cout << "FileInfoCacheLifetime set successfully." << std::endl;

    // Set FileNotFoundCacheLifetime
    lResult = RegSetValueEx(hKey, "FileNotFoundCacheLifetime", 0, REG_DWORD, (const BYTE*)&dwValue, sizeof(dwValue));
    if (lResult != ERROR_SUCCESS) {
        std::cerr << "Error setting FileNotFoundCacheLifetime: " << lResult << std::endl;
        RegCloseKey(hKey);
        return FALSE;
    }
    std::cout << "FileNotFoundCacheLifetime set successfully." << std::endl;

    // Set DirectoryCacheLifetime
    lResult = RegSetValueEx(hKey, "DirectoryCacheLifetime", 0, REG_DWORD, (const BYTE*)&dwValue, sizeof(dwValue));
    if (lResult != ERROR_SUCCESS) {
        std::cerr << "Error setting DirectoryCacheLifetime: " << lResult << std::endl;
        RegCloseKey(hKey);
        return FALSE;
    }
    std::cout << "DirectoryCacheLifetime set successfully." << std::endl;

    RegCloseKey(hKey);
    std::cout << "LanmanWorkstation parameters added successfully." << std::endl;
    return TRUE;
}

int main()
{                                                 
    LPCSTR cle = "SOFTWARE\\Borland";                                   
    LPCSTR cle2 = "SOFTWARE\\ComputerLine Electronique";                                                                     

    creation_cle(cle);
    creation_cle(cle2);
    
    creation_dossier();
    const char* folderPath = "C:\\CLE";             
    AddFullControlToEveryone(folderPath);           

    // Remplacer par la cle de registre souhaitee
    HKEY hKeyRoot = HKEY_CURRENT_USER;                                
    LPCTSTR subKey = _T("SOFTWARE\\ComputerLine Electronique");     
    LPCTSTR subKey2 = _T("SOFTWARE\\Borland");                          

    AddEveryoneFullControlToRegistryKey(hKeyRoot,subKey);
    AddEveryoneFullControlToRegistryKey(hKeyRoot,subKey2);
    AddEveryoneFullControlToRegistryKey2(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\WOW6432Node\\Borland"));

    //AddAllPermissionsToUsers(hKeyRoot, subKey2);

    //Desactivation de l'heritage des permissions et remplacement des autorisations des objets enfants
    DisableInheritanceAndReplaceChildPermissions(hKeyRoot, subKey);
    DisableInheritanceAndReplaceChildPermissions(hKeyRoot, subKey2);
    DisableInheritanceAndReplaceChildPermissions(HKEY_LOCAL_MACHINE, _T("SOFTWARE\\WOW6432Node\\Borland"));

    // First, enable the necessary privilege
    if (!EnablePrivilege(SE_TAKE_OWNERSHIP_NAME)) {
        std::cerr << "Unable to enable SE_TAKE_OWNERSHIP_NAME privilege." << std::endl;
        return FALSE;
    }

    // Then, add the LanmanWorkstation parameters
    if (!AddLanmanWorkstationParameters()) {
        std::cerr << "Failed to add LanmanWorkstation parameters." << std::endl;
    }

    // Finally, adjust the permissions
    AddEveryoneFullControlToRegistryKey2(HKEY_LOCAL_MACHINE, _T("SYSTEM\\CurrentControlSet\\services\\LanmanWorkstation\\Parameters"));
    return 0;            
}



 
