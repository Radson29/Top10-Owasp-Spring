
# OWASP Top 10 (2021) - Spring Framework

## A01:2021 Broken Access Control
<details>
<summary> 1. Zagrożenia związane z lokalnym włączeniem plików (Local File Inclusion, LFI)</summary>

### Opis podatności
Local File Inclusion (LFI) to podatność umożliwiająca nieautoryzowany dostęp do lokalnych plików na serwerze, co może prowadzić do ujawnienia wrażliwych informacji, takich jak konfiguracje, dane uwierzytelniające czy kod źródłowy. Występuje, gdy dane wejściowe użytkownika są niewłaściwie walidowane i wykorzystywane do dynamicznego ładowania plików.

---

### Przykład podatnego kodu
```java
@GetMapping("/loadFile")
public ResponseEntity<String> loadFile(@RequestParam String filePath) throws IOException {
    Path path = Paths.get(filePath); // Użytkownik dostarcza pełną ścieżkę
    String content = Files.readString(path); // Brak weryfikacji ścieżki
    return ResponseEntity.ok(content);
}
```

**Dlaczego podatny?**  
Kod pozwala użytkownikowi dostarczyć dowolną ścieżkę, co umożliwia dostęp do plików spoza zamierzonego katalogu.

---

### Przykład bezpiecznego kodu
```java
@GetMapping("/loadFile")
public ResponseEntity<String> loadFile(@RequestParam String fileName) throws IOException {
    // Ograniczamy dostęp tylko do określonego katalogu
    Path safeDirectory = Paths.get("safeDir").toAbsolutePath();
    Path filePath = safeDirectory.resolve(fileName).normalize();

    // Sprawdzamy, czy plik znajduje się w dozwolonym katalogu
    if (!filePath.startsWith(safeDirectory)) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access denied");
    }

    String content = Files.readString(filePath);
    return ResponseEntity.ok(content);
}
```

**Dlaczego bezpieczny?**  
- Ogranicza dostęp do określonego katalogu (`safeDir`).
- Używa funkcji `normalize` do usunięcia potencjalnych manipulacji ścieżką (`../`).
---
### Gotowe mechanizmy w Spring Security

#### Ochrona przed Local File Inclusion (LFI)
1. **Konfiguracja kontroli dostępu**:
   - Ogranicz dostęp do wybranych ścieżek za pomocą konfiguracji Spring Security.
   ```java
   @Configuration
   @EnableWebSecurity
   public class SecurityConfig extends WebSecurityConfigurerAdapter {
       
       @Override
       protected void configure(HttpSecurity http) throws Exception {
           http
               .authorizeRequests()
                   .antMatchers("/safeDir/**").permitAll() // Zezwalaj tylko na bezpieczne ścieżki
                   .anyRequest().denyAll() // Blokuj wszystkie inne żądania
               .and()
               .csrf().disable(); // Włącz w razie potrzeby, aby ochronić API
       }
   }
   ```

</details>

<details>
<summary>2. Zagrożenia związane z dostępem do obiektów poprzez middleware</summary>

### Opis podatności
Podatności związane z dostępem do obiektów poprzez middleware występują, gdy mechanizmy pośredniczące (np. serwisy lub komponenty w architekturze wielowarstwowej) nieprawidłowo zarządzają dostępem do zasobów. Może to prowadzić do uzyskania dostępu do obiektów lub danych przez nieautoryzowane podmioty.

### Domyślne ustawienia w frameworkach
Frameworki często oferują wbudowane mechanizmy autoryzacji i kontroli dostępu. Jednak niewłaściwa konfiguracja, pominięcie weryfikacji uprawnień lub nadmiarowe przywileje mogą doprowadzić do nieautoryzowanego dostępu.

---

### Przykład podatnego kodu
```java
@GetMapping("/getUserData")
public ResponseEntity<UserData> getUserData(@RequestParam Long userId) {
    // Brak weryfikacji, czy użytkownik ma prawo do dostępu do danych
    UserData userData = userService.findById(userId); 
    return ResponseEntity.ok(userData);
}
```

**Dlaczego podatny?**  
Brak weryfikacji uprawnień pozwala użytkownikowi uzyskać dostęp do danych innego użytkownika, podając dowolny `userId`.

---

### Przykład bezpiecznego kodu
```java
@GetMapping("/getUserData")
public ResponseEntity<UserData> getUserData(@RequestParam Long userId, Principal principal) {
    // Pobieramy dane zalogowanego użytkownika
    String currentUsername = principal.getName();
    UserData userData = userService.findById(userId);

    // Weryfikujemy, czy użytkownik ma prawo do dostępu do danych
    if (!userData.getUsername().equals(currentUsername)) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(null);
    }

    return ResponseEntity.ok(userData);
}
```

**Dlaczego bezpieczny?**  
- Weryfikuje, czy żądający użytkownik jest właścicielem danych, do których chce uzyskać dostęp.

---  
### Gotowe mechanizmy w Spring Security

#### Ochrona przed Object Access Middleware
1. **Adnotacje Spring Security**:
   - Użyj adnotacji takich jak `@PreAuthorize` i `@PostAuthorize` do walidacji uprawnień w serwisach.
   ```java
   @Service
   public class UserDataService {

       @PreAuthorize("#userId == authentication.principal.id")
       public UserData getUserData(Long userId) {
           return userRepository.findById(userId)
                   .orElseThrow(() -> new ResourceNotFoundException("User not found"));
       }
   }
   ```
2. **Weryfikacja użytkownika w Security Context**:
   - Korzystaj z `Principal` do identyfikacji użytkownika i sprawdzania jego uprawnień.
3. **Definiowanie ról i reguł dostępu**:
   - Skonfiguruj role i przypisz im odpowiednie zasoby w konfiguracji Spring Security.
   ```java
   @Override
   protected void configure(HttpSecurity http) throws Exception {
       http
           .authorizeRequests()
               .antMatchers("/admin/**").hasRole("ADMIN") // Tylko administratorzy
               .antMatchers("/user/**").hasAnyRole("USER", "ADMIN") // Użytkownicy i administratorzy
               .anyRequest().authenticated() // Wymagane uwierzytelnienie
           .and()
           .formLogin()
           .and()
           .logout();
   }
   ```

</details>
<details>
<summary>3. Zagrożenia związane z masowym przypisywaniem (Mass Assignment)</summary>

### Opis podatności
Mass Assignment to podatność, która występuje, gdy aplikacja automatycznie mapuje dane wejściowe użytkownika na atrybuty obiektu bez odpowiedniej walidacji. Może to pozwolić atakującemu na ustawienie wartości pól, które nie powinny być dostępne publicznie, takich jak role użytkownika, uprawnienia czy inne wrażliwe dane.

### Domyślne ustawienia w frameworkach
Niektóre frameworki, w tym Spring, umożliwiają masowe przypisywanie danych do obiektów (np. poprzez `@ModelAttribute`). Jednak bez odpowiedniej walidacji pól aplikacja może być podatna na nieautoryzowane zmiany.

---

### Przykład podatnego kodu
```java
@PostMapping("/updateUser")
public ResponseEntity<String> updateUser(@RequestBody User user) {
    // Bezpośrednie przypisanie danych użytkownika z żądania
    userRepository.save(user); // Brak weryfikacji modyfikowanych pól
    return ResponseEntity.ok("User updated successfully");
}
```

**Dlaczego podatny?**  
Atakujący może zmodyfikować pola, które nie powinny być dostępne (np. role, uprawnienia) przez dodanie ich w treści żądania.

---

### Przykład bezpiecznego kodu
```java
@PostMapping("/updateUser")
public ResponseEntity<String> updateUser(@RequestBody UserDto userDto, Principal principal) {
    // Pobieramy bieżącego użytkownika
    User currentUser = userRepository.findByUsername(principal.getName());

    // Ręczne przypisanie tylko dozwolonych pól
    currentUser.setName(userDto.getName());
    currentUser.setEmail(userDto.getEmail());

    userRepository.save(currentUser);
    return ResponseEntity.ok("User updated successfully");
}
```

**Dlaczego bezpieczny?**  
- Używa DTO (Data Transfer Object) do kontrolowania, które pola mogą być modyfikowane.
- Zapewnia ręczne przypisanie danych do obiektów, co ogranicza ryzyko modyfikacji wrażliwych pól.

---

### Gotowe mechanizmy w Spring Security

#### Ochrona przed Mass Assignment
1. **Użycie DTO**:
   - Korzystaj z klas DTO, aby określić, które pola użytkownik może przesyłać.
   - Przykład DTO:
     ```java
     public class UserDto {
         private String name;
         private String email;
         // Brak pól takich jak "role" czy "permissions"
     }
     ```
2. **Walidacja danych wejściowych**:
   - Użyj adnotacji takich jak `@Valid` oraz `@NotNull`, aby wymusić walidację danych przesyłanych przez użytkownika.
     ```java
     @PostMapping("/updateUser")
     public ResponseEntity<String> updateUser(@Valid @RequestBody UserDto userDto) {
         // Walidacja danych przed ich przetworzeniem
         return ResponseEntity.ok("Valid data received");
     }
     ```
</details>


