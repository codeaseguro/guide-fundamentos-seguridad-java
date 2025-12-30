# 🔑 Autorización

## Índice
1. [¿Qué es la Autorización?](#qué-es-la-autorización)
2. [Diferencia con Autenticación](#diferencia-con-autenticación)
3. [Modelos de Control de Acceso](#modelos-de-control-de-acceso)
4. [Implementaciones Comunes](#implementaciones-comunes)
5. [Ejemplos de Código](#ejemplos-de-código)
6. [Buenas Prácticas](#buenas-prácticas)

## ¿Qué es la Autorización?

**Autorización** es el proceso de **determinar qué puede hacer** un usuario autenticado.

Es la respuesta a la siguiente pregunta: > **Pregunta clave**: "¿Qué permisos tienes?"

### Analogía del Mundo Real

```
Hotel → Tarjeta de habitación
├─ Ya verificaron tu identidad en recepción (AUTENTICACIÓN).
├─ Te dieron una tarjeta que abre ciertas puertas.
├─ Tu tarjeta abre: Habitación 305, Gimnasio, Piscina.
└─ Tu tarjeta NO abre: Otras habitaciones, Oficinas del personal.

Esto es AUTORIZACIÓN → Qué puertas podes abrir.
```

## Diferencia con Autenticación

### Comparación

| Aspecto | Autenticación | Autorización |
|---------|---------------|--------------|
| **Responde** | ¿Quién eres? | ¿Qué podes hacer? |
| **Verifica** | Identidad | Permisos |
| **Ocurre** | Al inicio (login) | En cada acción |
| **Ejemplo** | Username + password | Verificar rol/permiso |
| **Falla** | Usuario desconocido | Acceso denegado |

## Modelos de Control de Acceso

### 1. Role-Based Access Control (RBAC)

Los permisos se asignan a **roles**, y los usuarios tienen roles.

```
Usuario → Rol → Permisos

Alice → Admin → [crear_usuario, eliminar_usuario, ver_logs]
Pepe → Editor → [editar_contenido, publicar_contenido]
Carol → Viewer → [ver_contenido]
```

#### Implementación RBAC

```java
public class RBACAuthorization {
    
    // Definir roles y sus permisos
    private static final Map<String, Set<String>> ROLE_PERMISSIONS = Map.of(
        "admin", Set.of("user.create", "user.delete", "user.view", "content.delete"),
        "editor", Set.of("content.create", "content.edit", "content.publish"),
        "viewer", Set.of("content.view")
    );
    
    public boolean hasPermission(User user, String permission) {
        // Obtener rol del usuario
        String role = user.getRole();
        
        // Verificar si el rol tiene el permiso
        Set<String> permissions = ROLE_PERMISSIONS.get(role);
        return permissions != null && permissions.contains(permission);
    }
    
    // Uso en código
    public void deleteUser(User currentUser, int userIdToDelete) {
        // Verificar autorización
        if (!hasPermission(currentUser, "user.delete")) {
            throw new AuthorizationException("No tienes permiso para eliminar usuarios");
        }
        
        // Realizar acción
        userRepository.delete(userIdToDelete);
    }
}
```

#### RBAC con Jerarquía de Roles

```java
public class HierarchicalRBAC {
    
    // Admin hereda permisos de Editor, Editor hereda de Viewer
    private static final Map<String, String> ROLE_HIERARCHY = Map.of(
        "admin", "editor",
        "editor", "viewer",
        "viewer", null
    );
    
    private static final Map<String, Set<String>> ROLE_PERMISSIONS = Map.of(
        "admin", Set.of("user.delete", "system.config"),
        "editor", Set.of("content.publish", "content.edit"),
        "viewer", Set.of("content.view")
    );
    
    public boolean hasPermission(User user, String permission) {
        String currentRole = user.getRole();
        
        // Verificar rol actual y todos los roles heredados
        while (currentRole != null) {
            Set<String> permissions = ROLE_PERMISSIONS.get(currentRole);
            
            if (permissions != null && permissions.contains(permission)) {
                return true;
            }
            
            // Subir en la jerarquía
            currentRole = ROLE_HIERARCHY.get(currentRole);
        }
        
        return false;
    }
    
    // Ejemplo de uso
    public static void main(String[] args) {
        User admin = new User("Alice", "admin");
        User editor = new User("Bob", "editor");
        User viewer = new User("Carol", "viewer");
        
        HierarchicalRBAC auth = new HierarchicalRBAC();
        
        // Admin puede hacer todo (hereda de editor y viewer)
        System.out.println("Admin puede ver contenido: " + 
            auth.hasPermission(admin, "content.view")); // true
        System.out.println("Admin puede eliminar usuarios: " + 
            auth.hasPermission(admin, "user.delete")); // true
        
        // Editor puede publicar pero no eliminar usuarios
        System.out.println("Editor puede publicar: " + 
            auth.hasPermission(editor, "content.publish")); // true
        System.out.println("Editor puede eliminar usuarios: " + 
            auth.hasPermission(editor, "user.delete")); // false
        
        // Viewer solo puede ver
        System.out.println("Viewer puede ver: " + 
            auth.hasPermission(viewer, "content.view")); // true
        System.out.println("Viewer puede editar: " + 
            auth.hasPermission(viewer, "content.edit")); // false
    }
}
```

### 2. Attribute-Based Access Control (ABAC)

Los permisos se basan en **atributos** del usuario, recurso y contexto.

```
Decisión = f(atributos_usuario, atributos_recurso, atributos_contexto)

Ejemplo:
Permitir SI:
  - usuario.departamento == recurso.departamento
  - recurso.clasificacion <= usuario.clearanceLevel
  - hora_actual ENTRE 9am Y 6pm
  - conexion.desde == "red_corporativa"
```

#### Implementación ABAC

```java
public class ABACAuthorization {
    
    public boolean canAccess(User user, Document document, Context context) {
        // Regla 1: Mismo departamento
        if (!user.getDepartment().equals(document.getDepartment())) {
            return false;
        }
        
        // Regla 2: Nivel de clasificación suficiente
        if (user.getClearanceLevel() < document.getClassificationLevel()) {
            return false;
        }
        
        // Regla 3: Horario laboral
        LocalTime now = context.getCurrentTime();
        if (now.isBefore(LocalTime.of(9, 0)) || now.isAfter(LocalTime.of(18, 0))) {
            return false;
        }
        
        // Regla 4: Red corporativa
        if (!context.getNetwork().equals("corporate")) {
            return false;
        }
        
        return true;
    }
    
    // Ejemplo de uso
    public Document accessDocument(User user, int documentId, Context context) {
        Document doc = documentRepository.findById(documentId);
        
        if (!canAccess(user, doc, context)) {
            throw new AuthorizationException("Acceso denegado al documento");
        }
        
        return doc;
    }
}

// Clases de soporte
class User {
    private String department;
    private int clearanceLevel; // 1-5
    
    // getters...
}

class Document {
    private String department;
    private int classificationLevel; // 1-5
    
    // getters...
}

class Context {
    private LocalTime currentTime;
    private String network;
    private String ipAddress;
    
    // getters...
}
```

### 3. Access Control Lists (ACL)

Cada recurso tiene una **lista de quién puede acceder** y qué puede hacer.

```
Documento "Proyecto Example":
├─ Alice: [read, write, delete]
├─ Pepe: [read, write]
└─ Carol: [read]
```

#### Implementación ACL

```java
public class ACLAuthorization {
    
    // Estructura de permisos por recurso
    class AccessControlEntry {
        String userId;
        Set<String> permissions; // read, write, delete, etc.
    }
    
    class AccessControlList {
        String resourceId;
        List<AccessControlEntry> entries;
    }
    
    private Map<String, AccessControlList> acls = new HashMap<>();
    
    public boolean hasPermission(String userId, String resourceId, String permission) {
        AccessControlList acl = acls.get(resourceId);
        
        if (acl == null) {
            return false; // No hay ACL definida
        }
        
        // Buscar entrada para este usuario
        for (AccessControlEntry entry : acl.entries) {
            if (entry.userId.equals(userId)) {
                return entry.permissions.contains(permission);
            }
        }
        
        return false; // Usuario no está en la ACL
    }
    
    // Agregar permiso
    public void grantPermission(String userId, String resourceId, String permission) {
        AccessControlList acl = acls.computeIfAbsent(
            resourceId, 
            k -> new AccessControlList()
        );
        
        // Buscar o crear entrada para el usuario
        AccessControlEntry entry = acl.entries.stream()
            .filter(e -> e.userId.equals(userId))
            .findFirst()
            .orElseGet(() -> {
                AccessControlEntry newEntry = new AccessControlEntry();
                newEntry.userId = userId;
                newEntry.permissions = new HashSet<>();
                acl.entries.add(newEntry);
                return newEntry;
            });
        
        entry.permissions.add(permission);
    }
    
    // Ejemplo de uso
    public void shareDocument(String ownerId, String documentId, String recipientId, String permission) {
        // Verificar que el que comparte sea el dueño
        if (!hasPermission(ownerId, documentId, "owner")) {
            throw new AuthorizationException("Solo el dueño puede compartir");
        }
        
        // Otorgar permiso
        grantPermission(recipientId, documentId, permission);
    }
}
```

### 4. Policy-Based Access Control (PBAC)

Los permisos se definen mediante **políticas** expresadas en un lenguaje específico.

```java
public class PBACAuthorization {
    
    interface Policy {
        boolean evaluate(User user, Resource resource, String action, Context context);
    }
    
    // Política: Solo el autor puede eliminar su propio contenido
    class OwnerDeletePolicy implements Policy {
        @Override
        public boolean evaluate(User user, Resource resource, String action, Context context) {
            if (!action.equals("delete")) {
                return true; // Esta política no aplica
            }
            
            return resource.getOwnerId().equals(user.getId());
        }
    }
    
    // Política: Documentos confidenciales solo en red corporativa
    class ConfidentialDocumentPolicy implements Policy {
        @Override
        public boolean evaluate(User user, Resource resource, String action, Context context) {
            if (!resource.isConfidential()) {
                return true; // No aplica a documentos no confidenciales
            }
            
            return context.getNetwork().equals("corporate");
        }
    }
    
    // Política: Aprobar presupuesto según monto
    class BudgetApprovalPolicy implements Policy {
        @Override
        public boolean evaluate(User user, Resource resource, String action, Context context) {
            if (!action.equals("approve_budget")) {
                return true;
            }
            
            double amount = ((BudgetRequest) resource).getAmount();
            
            // Managers pueden aprobar hasta $10,000
            if (user.hasRole("manager") && amount <= 10000) {
                return true;
            }
            
            // Directors pueden aprobar hasta $100,000
            if (user.hasRole("director") && amount <= 100000) {
                return true;
            }
            
            // VP puede aprobar cualquier monto
            return user.hasRole("vp");
        }
    }
    
    private List<Policy> policies = new ArrayList<>();
    
    public void addPolicy(Policy policy) {
        policies.add(policy);
    }
    
    public boolean isAuthorized(User user, Resource resource, String action, Context context) {
        // Todas las políticas deben pasar
        for (Policy policy : policies) {
            if (!policy.evaluate(user, resource, action, context)) {
                return false;
            }
        }
        
        return true;
    }
}
```

## Implementaciones Comunes

### 1. Anotaciones en Spring Security

```java
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    // Solo usuarios autenticados
    @GetMapping("/profile")
    @PreAuthorize("isAuthenticated()")
    public User getProfile() {
        return currentUser();
    }
    
    // Solo administradores
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUser(@PathVariable int id) {
        userService.delete(id);
    }
    
    // Permiso específico
    @PostMapping
    @PreAuthorize("hasAuthority('USER_CREATE')")
    public User createUser(@RequestBody User user) {
        return userService.create(user);
    }
    
    // Expresión compleja
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or @userService.isOwner(#id, authentication.name)")
    public User updateUser(@PathVariable int id, @RequestBody User user) {
        return userService.update(id, user);
    }
    
    // Solo el propietario o admin
    @GetMapping("/{id}/private")
    @PostAuthorize("returnObject.owner == authentication.name or hasRole('ADMIN')")
    public Document getPrivateDocument(@PathVariable int id) {
        return documentService.findById(id);
    }
}
```

### 2. Filtros de Autorización

```java
public class AuthorizationFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                   HttpServletResponse response, 
                                   FilterChain filterChain) 
            throws ServletException, IOException {
        
        // Extraer usuario autenticado
        User user = getAuthenticatedUser(request);
        
        if (user == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        
        // Verificar permisos según la ruta
        String path = request.getRequestURI();
        String method = request.getMethod();
        
        if (!hasPermissionForEndpoint(user, path, method)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("Acceso denegado");
            return;
        }
        
        // Continuar con la cadena
        filterChain.doFilter(request, response);
    }
    
    private boolean hasPermissionForEndpoint(User user, String path, String method) {
        // Admin puede todo
        if (user.hasRole("ADMIN")) {
            return true;
        }
        
        // Rutas públicas
        if (path.startsWith("/api/public/")) {
            return true;
        }
        
        // Verificar permisos específicos
        if (path.startsWith("/api/users/") && method.equals("DELETE")) {
            return user.hasPermission("user.delete");
        }
        
        if (path.startsWith("/api/documents/") && method.equals("POST")) {
            return user.hasPermission("document.create");
        }
        
        // Por defecto, denegar
        return false;
    }
}
```

### 3. Verificación Programática

```java
public class DocumentService {
    
    @Autowired
    private AuthorizationService authService;
    
    public Document getDocument(User user, int documentId) {
        Document doc = documentRepository.findById(documentId);
        
        // Verificar si el usuario puede ver este documento
        if (!authService.canView(user, doc)) {
            throw new AccessDeniedException("No tienes permiso para ver este documento");
        }
        
        return doc;
    }
    
    public void updateDocument(User user, int documentId, Document updates) {
        Document doc = documentRepository.findById(documentId);
        
        // Verificar permisos de edición
        if (!authService.canEdit(user, doc)) {
            throw new AccessDeniedException("No tienes permiso para editar");
        }
        
        // Verificar si puede cambiar ciertos campos
        if (updates.getClassification() != doc.getClassification()) {
            if (!authService.canChangeClassification(user, doc)) {
                throw new AccessDeniedException("No puedes cambiar la clasificación");
            }
        }
        
        documentRepository.update(doc);
    }
    
    public void deleteDocument(User user, int documentId) {
        Document doc = documentRepository.findById(documentId);
        
        // Solo el propietario o admin puede eliminar
        if (!doc.getOwnerId().equals(user.getId()) && !user.hasRole("ADMIN")) {
            throw new AccessDeniedException("Solo el propietario puede eliminar");
        }
        
        documentRepository.delete(documentId);
    }
}
```

### 4. Row-Level Security

Control de acceso a nivel de filas en la base de datos.

```java
public class RowLevelSecurity {
    
    // Filtrar resultados según permisos del usuario
    public List<Document> getDocuments(User user) {
        // Base query
        String sql = "SELECT * FROM documents WHERE ";
        List<String> conditions = new ArrayList<>();
        
        // Condición 1: Usuario es el propietario
        conditions.add("owner_id = ?");
        
        // Condición 2: Usuario tiene permiso explícito
        conditions.add("id IN (SELECT document_id FROM document_permissions WHERE user_id = ?)");
        
        // Condición 3: Documento es público
        conditions.add("is_public = true");
        
        // Si es admin, puede ver todo
        if (user.hasRole("ADMIN")) {
            sql = "SELECT * FROM documents";
        } else {
            sql += String.join(" OR ", conditions);
        }
        
        // Ejecutar query con parámetros
        return jdbcTemplate.query(sql, 
            new Object[]{user.getId(), user.getId()},
            documentRowMapper);
    }
    
    // Verificar acceso antes de operación
    public void updateDocument(User user, int documentId, Document updates) {
        // Verificar que el documento existe Y el usuario tiene acceso
        String sql = "SELECT * FROM documents WHERE id = ? AND (" +
                    "owner_id = ? OR " +
                    "id IN (SELECT document_id FROM document_permissions " +
                    "       WHERE user_id = ? AND permission = 'write'))";
        
        Document doc = jdbcTemplate.queryForObject(sql, 
            new Object[]{documentId, user.getId(), user.getId()},
            documentRowMapper);
        
        if (doc == null) {
            throw new AccessDeniedException("Documento no encontrado o sin permisos");
        }
        
        // Proceder con actualización
        
    }
}
```

## Patrones de Autorización

### 1. Verificar Propietario del Recurso

```java
public class OwnershipCheck {
    
    public void updatePost(User user, int postId, Post updates) {
        Post post = postRepository.findById(postId);
        
        // Verificar propiedad
        if (!post.getAuthorId().equals(user.getId())) {
            // Excepción: admins pueden editar cualquier post
            if (!user.hasRole("ADMIN")) {
                throw new AccessDeniedException("Solo el autor puede editar");
            }
        }
        
        postRepository.update(post);
    }
}
```

### 2. Autorización Basada en Relaciones

```java
public class RelationshipAuthorization {
    
    public void viewPrivateProfile(User viewer, User profileOwner) {
        // Casos donde se permite ver perfil privado:
        
        // 1. Es el propio perfil
        if (viewer.getId().equals(profileOwner.getId())) {
            return;
        }
        
        // 2. Son amigos
        if (friendshipRepository.areFriends(viewer.getId(), profileOwner.getId())) {
            return;
        }
        
        // 3. Viewer es moderador
        if (viewer.hasRole("MODERATOR")) {
            return;
        }
        
        throw new AccessDeniedException("No puedes ver este perfil privado");
    }
}
```

### 3. Autorización con Límites de Tiempo

```java
public class TemporalAuthorization {
    
    public void accessCourse(User user, int courseId) {
        Enrollment enrollment = enrollmentRepository.findByUserAndCourse(
            user.getId(), courseId
        );
        
        if (enrollment == null) {
            throw new AccessDeniedException("No estás inscrito en este curso");
        }
        
        // Verificar que la inscripción esté activa
        Instant now = Instant.now();
        if (now.isBefore(enrollment.getStartDate())) {
            throw new AccessDeniedException("El curso aún no ha comenzado");
        }
        
        if (now.isAfter(enrollment.getEndDate())) {
            throw new AccessDeniedException("Tu acceso al curso ha expirado");
        }
        
        // Acceso permitido
    }
}
```

### 4. Autorización en Cascada

```java
public class CascadingAuthorization {
    
    // Permisos se heredan de objetos padre
    public boolean canAccessFile(User user, File file) {
        // 1. Verificar permisos directos en el archivo
        if (hasDirectPermission(user, file)) {
            return true;
        }
        
        // 2. Verificar permisos en la carpeta padre
        Folder folder = file.getParentFolder();
        if (folder != null && hasPermission(user, folder, "read")) {
            return true;
        }
        
        // 3. Verificar permisos en carpetas ancestro
        while (folder != null && folder.getParent() != null) {
            folder = folder.getParent();
            if (hasPermission(user, folder, "read")) {
                return true;
            }
        }
        
        return false;
    }
}
```

## Buenas Prácticas

### ✅ QUE HACER

1. **Principio de mínimo privilegio**
   ```java
   // Dar solo los permisos necesarios
   user.grantPermission("article.read"); // ✓ Específico
   // NO: user.grantPermission("*"); // ✗ Demasiado amplio
   ```

2. **Verificar autorización en el backend, no solo en frontend**
   ```java
   // BIEN: Verificar en servidor
   @DeleteMapping("/users/{id}")
   public void deleteUser(@PathVariable int id) {
       if (!currentUser().hasRole("ADMIN")) {
           throw new AccessDeniedException();
       }
       userService.delete(id);
   }
   
   // MAL: Confiar solo en que el botón esté oculto en UI
   ```

3. **Denegar por defecto**
   ```java
   // BIEN
   public boolean hasPermission(User user, String permission) {
       return rolePermissions.get(user.getRole()).contains(permission);
       // Si el rol no existe, devuelve null → false
   }
   ```

4. **Logging de decisiones de autorización**
   ```java
   if (!hasPermission(user, "user.delete")) {
       logger.warn("Access denied: user={}, action=user.delete", user.getId());
       throw new AccessDeniedException();
   }
   ```

5. **Separar lógica de autorización**
   ```java
   // BIEN: Servicio dedicado
   @Service
   public class AuthorizationService {
       public boolean canDelete(User user, Resource resource) { ... }
   }
   
   // MAL: Lógica mezclada en controlador
   ```

### ❌ QUE NO HACER

1. **NO confiar en datos del cliente**
   ```java
   // MAL: Recibir rol desde el cliente
   public void updateUser(@RequestBody UpdateRequest req) {
       // req.role viene del cliente - ¡NO CONFIAR!
   }
   
   // BIEN: Obtener rol del token/sesión verificado
   ```

2. **NO usar authorization "mágica" invisible**
   ```java
   // MAL: Verificación oculta en ORM
   // Confuso y difícil de debuggear
   
   // BIEN: Verificación explícita
   if (!authService.canView(user, document)) {
       throw new AccessDeniedException();
   }
   ```

3. **NO hardcodear permisos**
   ```java
   // MAL
   if (user.getId() == 1 || user.getId() == 5) { ... }
   
   // BIEN
   if (user.hasRole("ADMIN")) { ... }
   ```

## Referencias

- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [NIST RBAC Standard](https://csrc.nist.gov/projects/role-based-access-control)
- [XACML (eXtensible Access Control Markup Language)](http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html)
- [Spring Security Authorization](https://docs.spring.io/spring-security/reference/servlet/authorization/index.html)