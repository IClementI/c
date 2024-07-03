# Gestionnaire de Permissions et Clés de Registre Windows

## Description

Ce programme permet de gérer les permissions des dossiers et des clés de registre dans un environnement Windows. Il offre diverses fonctionnalités pour ajouter des permissions, créer des dossiers et des clés de registre, désactiver l'héritage des permissions et ajuster les droits d'accès.

## Fonctionnalités

### 1. Ajouter le Contrôle Total au Groupe "Everyone" sur un Dossier

La fonction `AddFullControlToEveryone` permet d'ajouter le contrôle total pour le groupe "Everyone" à un dossier spécifié.

### 2. Ajouter le Groupe "Everyone" avec Contrôle Total à une Clé de Registre

La fonction `AddEveryoneFullControlToRegistryKey` ajoute le groupe "Everyone" avec contrôle total à une clé de registre dans `HKEY_CURRENT_USER`.

### 3. Activer un Privilège Spécifique

La fonction `EnablePrivilege` permet d'activer un privilège spécifique pour le processus en cours, nécessaire pour certaines opérations sur les clés de registre.

### 4. Prendre Possession d'une Clé de Registre

La fonction `TakeOwnership` permet de prendre possession d'une clé de registre dans `HKEY_LOCAL_MACHINE`.

### 5. Ajuster les Permissions d'une Clé de Registre

La fonction `AdjustPermissions` ajuste les permissions d'une clé de registre spécifiée pour permettre le contrôle total à "Everyone".

### 6. Ajouter le Contrôle Total pour "Everyone" à une Clé de Registre

La fonction `AddEveryoneFullControlToRegistryKey2` prend possession et ajuste les permissions d'une clé de registre pour ajouter le contrôle total pour "Everyone".

### 7. Créer des Clés de Registre

La fonction `creation_cle` permet de créer des clés de registre pour l'utilisateur courant (`HKEY_CURRENT_USER`).

### 8. Désactiver l'Héritage des Permissions et Remplacer les Permissions des Enfants

La fonction `DisableInheritanceAndReplaceChildPermissions` désactive l'héritage des permissions sur une clé de registre et remplace les permissions des sous-clés.

### 9. Créer des Dossiers

La fonction `creation_dossier` crée les dossiers spécifiés si ceux-ci n'existent pas déjà.

## Utilisation

### Ajouter le Contrôle Total à un Dossier

```cpp
AddFullControlToEveryone("C:\\Path\\To\\Folder");
```

### Ajouter le Groupe "Everyone" avec Contrôle Total à une Clé de Registre

```cpp
AddEveryoneFullControlToRegistryKey(HKEY_CURRENT_USER, _T("Software\\MyKey"));
```

### Prendre Possession d'une Clé de Registre

```cpp
TakeOwnership(HKEY_LOCAL_MACHINE, _T("Software\\MyKey"));
```

### Ajuster les Permissions d'une Clé de Registre

```cpp
AdjustPermissions(HKEY_LOCAL_MACHINE, _T("Software\\MyKey"));
```

### Créer des Clés de Registre

```cpp
creation_cle("Software\\MyNewKey");
```

### Désactiver l'Héritage des Permissions et Remplacer les Permissions des Enfants

```cpp
DisableInheritanceAndReplaceChildPermissions(HKEY_CURRENT_USER, _T("Software\\MyKey"));
```

### Créer des Dossiers

```cpp
creation_dossier();
```

## Remarques

- Assurez-vous d'exécuter le programme avec les privilèges administratifs nécessaires pour effectuer des modifications sur les clés de registre et les dossiers système.
- La modification des permissions et la prise de possession des clés de registre peuvent affecter le fonctionnement du système et des applications. Utilisez ces fonctions avec prudence.
