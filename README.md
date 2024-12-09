
# OWASP Top 10 (2021) - Spring Framework

## A01:2021 Broken Access Control

<details>
<summary> 🔴 1. Local File Inclusion, LFI</summary>

### Opis
Local File Inclusion (LFI) to podatność umożliwiająca nieautoryzowany dostęp do lokalnych plików na serwerze. W Springu może wystąpić, gdy dane wejściowe użytkownika są przekazywane bez walidacji jako ścieżka do pliku i używane do dynamicznego ładowania zasobów za pomocą klas takich jak `Files` czy `Paths`.

---

### Przykład podatności
```java
@GetMapping("/loadFile")
public ResponseEntity<String> loadFile(@RequestParam String filePath) throws IOException {
    // Użytkownik może dostarczyć dowolną ścieżkę, np. "../etc/passwd"
    Path path = Paths.get(filePath);
    String content = Files.readString(path); // Brak weryfikacji, czy ścieżka jest bezpieczna
    return ResponseEntity.ok(content);
}
```

**Dlaczego podatny?**  
- Spring umożliwia dynamiczne przetwarzanie parametrów żądania (np. `@RequestParam`), co przy braku walidacji pozwala na manipulację ścieżkami i dostęp do nieautoryzowanych plików.

---

### Skutki
- Możliwość odczytu plików systemowych (np. `/etc/passwd`).
- Ujawnienie wrażliwych informacji, takich jak hasła lub klucze.

---

### Zalecenia
```java
@GetMapping("/loadFile")
public ResponseEntity<String> loadFile(@RequestParam String fileName) throws IOException {
    // Definiujemy bezpieczny katalog
    Path safeDirectory = Paths.get("safeDir").toAbsolutePath();
    // Tworzymy ścieżkę dla pliku i normalizujemy ją
    Path filePath = safeDirectory.resolve(fileName).normalize();

    // Weryfikujemy, czy plik znajduje się w dozwolonym katalogu
    if (!filePath.startsWith(safeDirectory)) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access denied");
    }

    String content = Files.readString(filePath);
    return ResponseEntity.ok(content);
}
```

**Dlaczego bezpieczny?**  
- Ogranicza dostęp do katalogu `safeDir`.
- Używa `normalize`, aby zapobiec manipulacji ścieżkami typu `../`.

---

### Mechanizmy Spring Security
1. **Ograniczenie dostępu do zasobów**:
   ```java
   @Configuration
   @EnableWebSecurity
   public class SecurityConfig extends WebSecurityConfigurerAdapter {
       @Override
       protected void configure(HttpSecurity http) throws Exception {
           // Ustawiamy reguły dostępu:
           // - dostęp do ścieżek w katalogu "safeDir" jest dozwolony
           // - pozostałe ścieżki są blokowane
           http.authorizeRequests()
               .antMatchers("/safeDir/**").permitAll() // Dozwolone tylko "safeDir"
               .anyRequest().denyAll(); // Wszystko inne jest blokowane
       }
   }
   ```
   **Dlaczego bezpieczny?**  
   - Reguły Spring Security kontrolują dostęp do endpointów, ograniczając dostęp do katalogów.

</details>

<details>
<summary> 🔴 2. Object access middleware</summary>

### Opis
Podatności w Springu związane z dostępem do obiektów mogą wystąpić, gdy brak jest walidacji danych użytkownika lub kontroli dostępu. Przykładowo, brak weryfikacji użytkownika przy pobieraniu danych za pomocą metod serwisowych może prowadzić do eskalacji uprawnień.

---

### Przykład podatności
```java
@GetMapping("/getUserData")
public ResponseEntity<UserData> getUserData(@RequestParam Long userId) {
    // Metoda pobiera dane dowolnego użytkownika bez sprawdzania uprawnień
    UserData userData = userService.findById(userId); 
    return ResponseEntity.ok(userData);
}
```

**Dlaczego podatny?**  
- Brak weryfikacji, czy zalogowany użytkownik jest właścicielem danych, które chce uzyskać.
- Spring umożliwia łatwe mapowanie parametrów (np. `@RequestParam`), ale to programista odpowiada za kontrolę dostępu.

---

### Skutki
- Nieautoryzowany dostęp do danych innego użytkownika.
- Naruszenie poufności danych.

---

### Zalecenia
```java
@GetMapping("/getUserData")
public ResponseEntity<UserData> getUserData(@RequestParam Long userId, Principal principal) {
    // Pobieramy nazwę użytkownika z kontekstu bezpieczeństwa
    String currentUsername = principal.getName();
    UserData userData = userService.findById(userId);

    // Sprawdzamy, czy zalogowany użytkownik ma dostęp do danych
    if (!userData.getUsername().equals(currentUsername)) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(null);
    }

    return ResponseEntity.ok(userData);
}
```

**Dlaczego bezpieczny?**  
- Sprawdza, czy dane należą do użytkownika wysyłającego żądanie.

---

### Mechanizmy Spring Security
1. **Weryfikacja uprawnień za pomocą adnotacji**:
   ```java
   @Service
   public class UserService {
       // Adnotacja @PreAuthorize sprawdza, czy ID użytkownika pasuje do ID z kontekstu
       @PreAuthorize("#userId == authentication.principal.id")
       public UserData getUserData(Long userId) {
           return userRepository.findById(userId)
               .orElseThrow(() -> new RuntimeException("User not found"));
       }
   }
   ```
   **Dlaczego bezpieczny?**  
   - Adnotacja `@PreAuthorize` weryfikuje uprawnienia przed wykonaniem metody.

</details>

<details>
<summary>3. Mass Assignment</summary>

### Opis
Mass Assignment w Springu może wystąpić, gdy dane wejściowe są mapowane bezpośrednio na obiekt modelu (np. `@RequestBody`). Przykładowo, użytkownik może manipulować przesyłanymi danymi, aby zmienić pola, do których nie powinien mieć dostępu.

---

### Przykład podatności
```java
@PostMapping("/updateUser")
public ResponseEntity<String> updateUser(@RequestBody User user) {
    // Bezpośrednie przypisanie danych użytkownika z żądania do modelu
    userRepository.save(user); // Brak kontroli nad modyfikowanymi polami
    return ResponseEntity.ok("User updated");
}
```

**Dlaczego podatny?**  
- Spring automatycznie mapuje dane JSON na obiekt, co pozwala na nieautoryzowane zmiany, np. ustawienie pola `role`.

---

### Skutki
- Nieautoryzowane modyfikacje wrażliwych pól, takich jak role użytkownika.
- Możliwość eskalacji uprawnień.

---

### Zalecenia
```java
@PostMapping("/updateUser")
public ResponseEntity<String> updateUser(@RequestBody UserDto userDto, Principal principal) {
    // Pobieramy dane zalogowanego użytkownika
    User currentUser = userRepository.findByUsername(principal.getName());

    // Ręczne przypisanie tylko wybranych pól
    currentUser.setName(userDto.getName());
    currentUser.setEmail(userDto.getEmail());

    userRepository.save(currentUser);
    return ResponseEntity.ok("User updated");
}
```

**Dlaczego bezpieczny?**  
- Wykorzystuje DTO do ograniczenia modyfikowanych pól.
- Zapewnia pełną kontrolę nad procesem aktualizacji.

---

### Mechanizmy Spring Security
1. **Walidacja danych wejściowych za pomocą DTO**:
   ```java
   public class UserDto {
       @NotBlank
       private String name;

       @Email
       private String email;
   }
   ```

2. **Bezpieczne mapowanie danych w kontrolerze**:
   ```java
   @PostMapping("/updateUser")
   public ResponseEntity<String> updateUser(@Valid @RequestBody UserDto userDto) {
       // Tylko dane zgodne z DTO zostaną zaakceptowane
       return ResponseEntity.ok("User updated");
   }
   ```

</details>

<details>
<summary>🔴 4. Insecure Direct Object Reference (IDOR)</summary>

### Opis
Insecure Direct Object Reference (IDOR) to podatność, która występuje, gdy aplikacja pozwala użytkownikowi na bezpośredni dostęp do zasobów (np. rekordów w bazie danych) za pomocą identyfikatorów, takich jak ID. W Springu podatność ta może wystąpić, jeśli parametry takie jak `@RequestParam` czy `@PathVariable` nie są odpowiednio weryfikowane w kontekście dostępu użytkownika do danego zasobu.

---

### Przykład podatności
```java
@GetMapping("/documents/{docId}")
public ResponseEntity<Document> getDocument(@PathVariable Long docId) {
    // Pobieramy dokument z bazy danych na podstawie ID przekazanego w żądaniu
    Document document = documentRepository.findById(docId)
            .orElseThrow(() -> new RuntimeException("Document not found"));
    return ResponseEntity.ok(document);
}
```

**Dlaczego podatny?**  
- Użytkownik może manipulować parametrem `docId` w żądaniu, aby uzyskać dostęp do dokumentów, do których nie powinien mieć dostępu.
- Brak weryfikacji, czy zalogowany użytkownik ma uprawnienia do danego zasobu.

---

### Skutki
- Nieautoryzowany dostęp do danych innych użytkowników.
- Ujawnienie poufnych informacji, takich jak dokumenty, dane osobowe czy transakcje.

---

### Zalecenia
```java
@GetMapping("/documents/{docId}")
public ResponseEntity<Document> getDocument(@PathVariable Long docId, Principal principal) {
    // Pobieramy nazwę użytkownika z kontekstu bezpieczeństwa
    String currentUsername = principal.getName();

    // Pobieramy dokument z bazy danych
    Document document = documentRepository.findById(docId)
            .orElseThrow(() -> new RuntimeException("Document not found"));

    // Sprawdzamy, czy dokument należy do zalogowanego użytkownika
    if (!document.getOwner().equals(currentUsername)) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(null);
    }

    return ResponseEntity.ok(document);
}
```

**Dlaczego bezpieczny?**  
- Weryfikuje, czy dokument należy do zalogowanego użytkownika.
- Ogranicza dostęp do zasobów na podstawie tożsamości użytkownika.

---

### Mechanizmy Spring Security
1. **Kontrola dostępu z użyciem `@PreAuthorize`**:
   ```java
   @Service
   public class DocumentService {
       // Adnotacja weryfikuje, czy użytkownik jest właścicielem dokumentu przed wykonaniem metody
       @PreAuthorize("@documentSecurityService.isOwner(#docId, authentication.name)")
       public Document getDocument(Long docId) {
           return documentRepository.findById(docId)
                   .orElseThrow(() -> new RuntimeException("Document not found"));
       }
   }

   @Component
   public class DocumentSecurityService {
       public boolean isOwner(Long docId, String username) {
           Document document = documentRepository.findById(docId).orElse(null);
           return document != null && document.getOwner().equals(username);
       }
   }
   ```

   **Dlaczego bezpieczny?**  
   - Adnotacja `@PreAuthorize` wymusza weryfikację uprawnień przed wykonaniem metody.
   - Logika w klasie `DocumentSecurityService` dokładnie sprawdza, czy użytkownik jest właścicielem zasobu.

2. **Definiowanie ról i reguł dostępu**:
   ```java
   @Override
   protected void configure(HttpSecurity http) throws Exception {
       http.authorizeRequests()
           .antMatchers("/documents/**").authenticated() // Dostęp do dokumentów tylko dla zalogowanych użytkowników
           .anyRequest().denyAll();
   }
   ```

   **Dlaczego bezpieczny?**  
   - Ogranicza dostęp do endpointów tylko dla uwierzytelnionych użytkowników.
   - Blokuje nieautoryzowany dostęp do wszystkich innych zasobów.

</details>

## A02:2021 Cryptographic Failures

<details>
<summary>🔴 1. Weak Encoding for Password</summary>

### Opis
Podatność związana z niewłaściwym hashowaniem haseł występuje, gdy aplikacja używa słabych funkcji hashujących, takich jak MD5 lub SHA-1, które są podatne na ataki siłowe (brute force) lub kolizje. W Springu ta podatność może wystąpić, jeśli implementacja przechowywania haseł nie wykorzystuje odpowiednich algorytmów, takich jak BCrypt.

---

### Przykład podatności
```java
@Service
public class UserService {

    // Hashowanie hasła za pomocą MD5 (słaby algorytm)
    public String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }
}
```

**Dlaczego podatny?**  
- MD5 jest przestarzałym algorytmem hashującym, podatnym na ataki brute force i kolizje.
- Brak mechanizmu saltingu, co zwiększa ryzyko złamania haseł.

---

### Skutki
- Nieautoryzowany dostęp do kont użytkowników w przypadku złamania haseł.
- Naruszenie poufności danych.

---

### Zalecenia
```java
@Service
public class UserService {

    // Hashowanie hasła za pomocą BCrypt
    public String hashPassword(String password) {
        return new BCryptPasswordEncoder().encode(password);
    }
}
```

**Dlaczego bezpieczny?**  
- BCrypt został zaprojektowany specjalnie do przechowywania haseł, zapewniając wbudowany mechanizm saltingu.
- Jego mechanizm adaptacyjny zwiększa czas hashowania w miarę wzrostu mocy obliczeniowej atakujących.

---

### Mechanizmy Spring Security
1. **Użycie wbudowanego `PasswordEncoder`**:
   ```java
   @Configuration
   public class SecurityConfig {
       @Bean
       public PasswordEncoder passwordEncoder() {
           // Konfigurujemy BCryptPasswordEncoder jako domyślny mechanizm hashowania
           return new BCryptPasswordEncoder();
       }
   }
   ```

   **Dlaczego bezpieczny?**  
   - Spring Security rekomenduje użycie `BCryptPasswordEncoder`, który jest zgodny z najlepszymi praktykami dotyczącymi przechowywania haseł.

2. **Weryfikacja hasła**:
   ```java
   @Service
   public class AuthenticationService {
       @Autowired
       private PasswordEncoder passwordEncoder;

       public boolean verifyPassword(String rawPassword, String hashedPassword) {
           // Sprawdzanie hasła za pomocą BCrypt
           return passwordEncoder.matches(rawPassword, hashedPassword);
       }
   }
   ```

   **Dlaczego bezpieczny?**  
   - Funkcja `matches` zapewnia poprawne porównanie hasła w formie jawnej z jego wersją zahashowaną.

</details>

<details>
<summary> 🔴 2. Use of Hard-coded Cryptographic Key</summary>

### Opis
Podatność związana z używaniem zaszytych na stałe (hard-coded) kluczy kryptograficznych występuje, gdy aplikacja przechowuje klucz szyfrujący bezpośrednio w kodzie źródłowym. Może to prowadzić do ujawnienia klucza i umożliwienia atakującym odszyfrowania poufnych danych. W Springu problem ten może wystąpić, gdy klucz jest zapisany w zmiennej w kodzie lub w plikach konfiguracyjnych bez odpowiedniego zabezpieczenia.

---

### Przykład podatności
```java
@Service
public class EncryptionService {

    // Zaszyty na stałe klucz kryptograficzny (podatny)
    private static final String SECRET_KEY = "hardcoded_key_12345";

    public String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));
    }
}
```

**Dlaczego podatny?**  
- Klucz kryptograficzny jest zapisany w kodzie i może być łatwo odczytany przez atakujących.

---

### Skutki
- Możliwość odszyfrowania poufnych danych przez osoby trzecie.
- Naruszenie poufności danych użytkowników.

---

### Zalecenia
```java
@Service
public class EncryptionService {

    // Klucz kryptograficzny jest przechowywany w bezpiecznym magazynie, np. w pliku konfiguracyjnym lub systemie zarządzania sekretami
    @Value("${encryption.secret-key}")
    private String secretKey;

    public String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));
    }
}
```

**Dlaczego bezpieczny?**  
- Klucz kryptograficzny jest przechowywany poza kodem źródłowym, np. w `application.properties` lub w systemie zarządzania sekretami (Vault, AWS Secrets Manager).
- Dostęp do klucza jest ograniczony odpowiednimi mechanizmami uprawnień.

---

### Mechanizmy Spring Security
1. **Przechowywanie klucza w pliku konfiguracyjnym**:
   ```properties
   # application.properties
   encryption.secret-key=secure_random_generated_key
   ```

   **Dlaczego bezpieczne?**  
   - Plik konfiguracyjny może być chroniony odpowiednimi uprawnieniami dostępu do systemu operacyjnego.
   - Klucz nie jest zaszyty w kodzie, co utrudnia jego wyciek.

2. **Użycie systemu zarządzania sekretami**:
   - Integracja z narzędziami takimi jak HashiCorp Vault, AWS Secrets Manager czy Azure Key Vault.
   - Przykład pobierania klucza z Vault:
     ```java
     @Service
     public class EncryptionService {

         @Autowired
         private VaultTemplate vaultTemplate;

         public String getSecretKey() {
             return vaultTemplate.read("secret/encryption").getData().get("key");
         }
     }
     ```

   **Dlaczego bezpieczne?**  
   - Klucz jest przechowywany w dedykowanym, bezpiecznym magazynie, a dostęp do niego wymaga odpowiednich uprawnień.

</details>
<details>
<summary>🔴 3. Cleartext Transmission of Sensitive Information</summary>

### Opis
Podatność ta występuje, gdy aplikacja przesyła poufne informacje (np. dane logowania, dane osobowe, czy numery kart kredytowych) w formie jawnego tekstu (cleartext), bez odpowiedniego zabezpieczenia protokołem szyfrowania, takim jak HTTPS. W Springu problem ten może wystąpić, jeśli endpointy są wystawione na HTTP zamiast HTTPS lub jeśli wrażliwe dane są przesyłane jako jawny tekst w odpowiedziach lub nagłówkach HTTP.

---

### Przykład podatności
```java
@RestController
public class LoginController {

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest) {
        // Wrażliwe dane użytkownika są zwracane w jawny sposób
        return ResponseEntity.ok("User logged in with password: " + loginRequest.getPassword());
    }
}
```

**Dlaczego podatny?**  
- Endpoint `/login` jest dostępny przez HTTP, co umożliwia przechwycenie danych podczas transmisji (np. za pomocą ataku typu Man-in-the-Middle).
- Hasło użytkownika jest przesyłane jako część odpowiedzi w jawny sposób.

---

### Skutki
- Przejęcie poufnych danych użytkownika, takich jak login i hasło.
- Możliwość nieautoryzowanego dostępu do systemu.

---

### Zalecenia
```java
@RestController
public class LoginController {

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest) {
        // Minimalizujemy wrażliwe dane w odpowiedzi
        return ResponseEntity.ok("User logged in successfully.");
    }
}
```

**Dlaczego bezpieczny?**  
- Wrażliwe informacje, takie jak hasło, nie są przesyłane w odpowiedzi.
- Dane są przesyłane wyłącznie przez HTTPS, co zabezpiecza je przed przechwyceniem.

---

### Mechanizmy Spring Security
1. **Wymuszanie HTTPS**:
   - Można skonfigurować aplikację Spring do wymuszania HTTPS, dodając poniższą konfigurację:
   ```java
   @Configuration
   public class SecurityConfig extends WebSecurityConfigurerAdapter {

       @Override
       protected void configure(HttpSecurity http) throws Exception {
           http.requiresChannel()
               .anyRequest()
               .requiresSecure(); // Wymusza HTTPS dla wszystkich żądań
       }
   }
   ```

   **Dlaczego bezpieczne?**  
   - Spring Security automatycznie przekierowuje wszystkie żądania HTTP na HTTPS.

2. **Dodanie certyfikatu SSL w `application.properties`**:
   ```properties
   server.ssl.key-store=classpath:keystore.p12
   server.ssl.key-store-password=yourPassword
   server.ssl.key-store-type=PKCS12
   server.port=8443
   ```

   **Dlaczego bezpieczne?**  
   - Dane są szyfrowane podczas transmisji przy użyciu protokołu HTTPS z certyfikatem SSL/TLS.
</details>

## A03:2021 Injection

<details>
<summary>🔴 1. Remote Code Execution (RCE)</summary>

### Opis
Remote Code Execution (RCE) to podatność, która pozwala atakującemu na wstrzyknięcie i wykonanie dowolnego kodu na serwerze. W Springu ta podatność może wystąpić w dwóch głównych kontekstach:
1. **Spring Expression Language (SpEL):** Jeśli użytkownik ma kontrolę nad wyrażeniami SpEL i są one wykonywane bez ograniczeń.
2. **Deserializacja obiektów:** Gdy aplikacja deserializuje niezaufane dane bez odpowiedniej walidacji.

---

### Przykład podatności: SpEL
```java
@RestController
public class SpELController {

    @PostMapping("/evaluate")
    public ResponseEntity<String> evaluateExpression(@RequestParam String expression) {
        // Wykonanie wyrażenia SpEL dostarczonego przez użytkownika
        ExpressionParser parser = new SpelExpressionParser();
        Expression exp = parser.parseExpression(expression);
        String result = exp.getValue().toString();
        return ResponseEntity.ok("Result: " + result);
    }
}
```

**Dlaczego podatny?**  
- Użytkownik może wstrzyknąć złośliwe wyrażenie SpEL, takie jak `T(java.lang.Runtime).getRuntime().exec("rm -rf /")`, co pozwoli na wykonanie dowolnego polecenia systemowego.

---

### Przykład podatności: Deserializacja obiektów
```java
@RestController
public class DeserializationController {

    @PostMapping("/deserialize")
    public ResponseEntity<Object> deserialize(@RequestBody byte[] data) throws IOException, ClassNotFoundException {
        // Deserializacja danych dostarczonych przez użytkownika
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object obj = ois.readObject();
        return ResponseEntity.ok(obj);
    }
}
```

**Dlaczego podatny?**  
- Deserializacja niezaufanych danych umożliwia atakującemu dostarczenie złośliwego obiektu, który może wykonać niebezpieczne operacje, takie jak otwieranie połączeń sieciowych lub modyfikacja plików.

---

### Skutki
- Wykonanie dowolnego kodu na serwerze.
- Przejęcie kontroli nad aplikacją lub serwerem.
- Utrata poufności, integralności lub dostępności danych.

---

### Zalecenia: SpEL
```java
@RestController
public class SpELController {

    @PostMapping("/evaluate")
    public ResponseEntity<String> evaluateExpression(@RequestParam String expression) {
        // Ograniczenie wyrażeń SpEL do prostych operacji matematycznych
        if (!expression.matches("[0-9+\-*/()]*")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid expression");
        }

        ExpressionParser parser = new SpelExpressionParser();
        Expression exp = parser.parseExpression(expression);
        String result = exp.getValue().toString();
        return ResponseEntity.ok("Result: " + result);
    }
}
```

**Dlaczego bezpieczny?**  
- Ogranicza dopuszczalne wyrażenia do prostych operacji matematycznych.
- Nie pozwala na wykonanie potencjalnie niebezpiecznych wyrażeń SpEL.

---

### Zalecenia: Deserializacja
```java
@RestController
public class DeserializationController {

    @PostMapping("/deserialize")
    public ResponseEntity<Object> deserialize(@RequestBody byte[] data) throws IOException, ClassNotFoundException {
        // Zastosowanie białej listy dozwolonych klas
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data)) {
            @Override
            protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
                if (!"com.example.SafeClass".equals(desc.getName())) {
                    throw new InvalidClassException("Unauthorized deserialization attempt: " + desc.getName());
                }
                return super.resolveClass(desc);
            }
        };

        Object obj = ois.readObject();
        return ResponseEntity.ok(obj);
    }
}
```

**Dlaczego bezpieczny?**  
- Implementuje białą listę klas, które mogą być deserializowane.
- Uniemożliwia wykonanie złośliwych obiektów dostarczonych przez atakującego.

---

### Mechanizmy Spring Security
1. **Wyłącz SpEL w miejscach, gdzie jest to możliwe**:
   - Jeśli SpEL nie jest konieczne, ogranicz jego użycie w konfiguracji Springa lub użyj bardziej ograniczonych wyrażeń.

2. **Walidacja danych wejściowych**:
   - Weryfikuj i waliduj dane wejściowe użytkownika przed ich przetwarzaniem.
   ```java
   @PostMapping("/evaluate")
   public ResponseEntity<String> validateAndEvaluate(@RequestParam @Pattern(regexp = "[0-9+\-*/()]*") String expression) {
       // Przetwarzanie wyrażenia po walidacji
       return ResponseEntity.ok("Validated and processed");
   }
   ```

3. **Unikaj deserializacji niezaufanych danych**:
   - Korzystaj z bezpiecznych formatów przesyłania danych, takich jak JSON czy protokoły typu Protobuf, zamiast Java Serialization.

</details>

<details>
<summary>🔴 2. Cross-Site Scripting (XSS)</summary>

### Opis
Cross-Site Scripting (XSS) to podatność, która występuje, gdy aplikacja wstrzykuje niesprawdzone dane użytkownika do odpowiedzi HTML, umożliwiając wykonanie złośliwego kodu JavaScript w przeglądarce ofiary. W Springu podatność ta może wystąpić, jeśli dane wejściowe użytkownika są bezpośrednio renderowane na stronie bez odpowiedniego zabezpieczenia.

---

### Przykład podatności
```java
@RestController
public class XSSController {

    @GetMapping("/greet")
    public String greetUser(@RequestParam String name) {
        // Bezpośrednie wstawienie danych użytkownika w odpowiedzi HTML
        return "<html><body>Hello, " + name + "!</body></html>";
    }
}
```

**Dlaczego podatny?**  
- Dane wejściowe użytkownika (`name`) są wstawiane bez walidacji lub escapingu.
- Atakujący może przesłać złośliwy kod, np. `<script>alert('Hacked!')</script>`, który zostanie wykonany w przeglądarce użytkownika.

---

### Skutki
- Wykonanie złośliwego kodu JavaScript w przeglądarce ofiary.
- Kradzież danych sesyjnych lub poufnych informacji.
- Podszywanie się pod użytkownika (session hijacking).

---

### Zalecenia
1. **Escaping danych wyjściowych**:
   ```java
   @RestController
   public class XSSController {

       @GetMapping("/greet")
       public String greetUser(@RequestParam String name) {
           // Escaping danych użytkownika
           String escapedName = HtmlUtils.htmlEscape(name);
           return "<html><body>Hello, " + escapedName + "!</body></html>";
       }
   }
   ```

   **Dlaczego bezpieczny?**  
   - Funkcja `HtmlUtils.htmlEscape` zamienia specjalne znaki na ich bezpieczne odpowiedniki HTML (np. `<` na `&lt;`).

2. **Użycie szablonów JSP lub Thymeleaf z automatycznym escapowaniem**:
   - Thymeleaf automatycznie escapuje dane użytkownika:
     ```html
     <p th:text="${name}">Hello, User!</p>
     ```

---

### Mechanizmy Spring Security
1. **SecurityFilterChain**:
   - Spring Security domyślnie zapewnia ochronę przed XSS za pomocą `SecurityFilterChain`, który filtruje dane wejściowe i odpowiedzi HTTP.
   - Konfiguracja w Spring Boot:
     ```java
     @Configuration
     public class SecurityConfig {

         @Bean
         public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
             http
                 .csrf() // Włącz ochronę przed CSRF
                 .and()
                 .headers()
                 .xssProtection()
                 .block(false); // Włącza podstawowe zabezpieczenia XSS
             return http.build();
         }
     }
     ```

     **Dlaczego bezpieczne?**  
     - `SecurityFilterChain` automatycznie filtruje i blokuje potencjalne ataki XSS.

2. **Użycie CSP (Content Security Policy)**:
   - Dodanie nagłówka Content-Security-Policy do odpowiedzi:
     ```java
     @Configuration
     public class SecurityConfig {

         @Bean
         public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
             http
                 .headers()
                 .contentSecurityPolicy("script-src 'self'");
             return http.build();
         }
     }
     ```

     **Dlaczego bezpieczne?**  
     - CSP ogranicza możliwość wykonywania skryptów tylko do zaufanych źródeł.

3. **Walidacja danych wejściowych**:
   - Waliduj dane użytkownika przed ich przetwarzaniem:
     ```java
     @GetMapping("/greet")
     public String validateAndGreetUser(@RequestParam @Size(max = 50) String name) {
         return "<html><body>Hello, " + HtmlUtils.htmlEscape(name) + "!</body></html>";
     }
     ```

     **Dlaczego bezpieczne?**  
     - Walidacja ogranicza wielkość i zakres akceptowanych danych wejściowych.

</details>

<details>
<summary>🔴 3. Cross-Site Request Forgery (CSRF)</summary>

### Opis
Cross-Site Request Forgery (CSRF) to podatność, w której atakujący wykorzystuje uwierzytelnioną sesję użytkownika do wykonania nieautoryzowanych akcji w aplikacji webowej. W Springu podatność ta może wystąpić, jeśli aplikacja nie stosuje tokenów CSRF lub gdy endpointy API są niewłaściwie chronione.

---

### Przykład podatności
```java
@RestController
public class CSRFController {

    @PostMapping("/transfer")
    public ResponseEntity<String> transferFunds(@RequestParam String account, @RequestParam double amount) {
        // Brak weryfikacji, czy żądanie pochodzi od autoryzowanego użytkownika
        return ResponseEntity.ok("Transferred " + amount + " to " + account);
    }
}
```

**Dlaczego podatny?**  
- Endpoint `/transfer` nie wymaga żadnego mechanizmu weryfikacji, czy żądanie pochodzi z zaufanego źródła.
- Atakujący może osadzić złośliwy formularz HTML w swojej witrynie, aby wymusić żądanie na uwierzytelnionym użytkowniku.

---

### Skutki
- Nieautoryzowane wykonanie akcji, takich jak przelewy, zmiana danych użytkownika lub modyfikacja ustawień.
- Naruszenie integralności i bezpieczeństwa danych.

---

### Zalecenia
1. **Włączenie ochrony CSRF w Spring Security**:
   - Domyślnie Spring Security chroni przed CSRF. Można to skonfigurować w `SecurityFilterChain`:
     ```java
     @Configuration
     public class SecurityConfig {

         @Bean
         public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
             http
                 .csrf() // Włącza ochronę przed CSRF
                 .and()
                 .authorizeRequests()
                 .anyRequest().authenticated(); // Wszystkie żądania muszą być uwierzytelnione
             return http.build();
         }
     }
     ```

     **Dlaczego bezpieczne?**  
     - Token CSRF jest generowany dla każdego żądania i weryfikowany na serwerze.

2. **Użycie tokenów CSRF w żądaniach**:
   - Token CSRF należy przesyłać w każdym żądaniu POST:
     ```html
     <form method="POST" action="/transfer">
         <input type="hidden" name="_csrf" value="${_csrf.token}" />
         <input type="text" name="account" placeholder="Account" />
         <input type="number" name="amount" placeholder="Amount" />
         <button type="submit">Transfer</button>
     </form>
     ```

     **Dlaczego bezpieczne?**  
     - Serwer weryfikuje poprawność tokenu CSRF przed wykonaniem akcji.

3. **Wyłączanie ochrony CSRF dla endpointów API (jeśli to konieczne)**:
   - Jeśli API korzysta z tokenów uwierzytelniających, można wyłączyć CSRF:
     ```java
     @Configuration
     public class SecurityConfig {

         @Bean
         public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
             http
                 .csrf().disable() // Wyłącza CSRF dla REST API
                 .authorizeRequests()
                 .anyRequest().authenticated(); // Wszystkie żądania muszą być uwierzytelnione
             return http.build();
         }
     }
     ```

     **Dlaczego bezpieczne?**  
     - Tokeny uwierzytelniające (np. JWT) zastępują funkcję tokenów CSRF w przypadku API.

4. **Dodanie nagłówków `SameSite` dla ciasteczek**:
   - Ustaw nagłówek `SameSite` na `Strict` lub `Lax`:
     ```java
     @Bean
     public WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> cookieConfig() {
         return factory -> factory.addInitializers(
             new WebServerInitializer(new SameSiteCookieConfig("Strict")));
     }
     ```

     **Dlaczego bezpieczne?**  
     - Ciasteczka nie są przesyłane w żądaniach pochodzących z innych domen.

</details>

<details>
<summary>🔴 4. SQL Injection (SQLi)</summary>

### Opis
SQL Injection (SQLi) to podatność, w której atakujący wstrzykuje złośliwy kod SQL do zapytania, manipulując danymi wejściowymi. W Spring Data JPA problem ten może wystąpić, gdy programista używa zapytań dynamicznych zbudowanych w oparciu o dane użytkownika bez ich odpowiedniego zabezpieczenia.

---

### Przykład podatności
```java
@Repository
public class UserRepository {

    @PersistenceContext
    private EntityManager entityManager;

    public List<User> findByUsername(String username) {
        // Dynamiczne zapytanie SQL z wstrzykniętymi danymi użytkownika
        String query = "SELECT u FROM User u WHERE u.username = '" + username + "'";
        return entityManager.createQuery(query, User.class).getResultList();
    }
}
```

**Dlaczego podatny?**  
- Użytkownik może przesłać złośliwy ciąg znaków, np. `' OR '1'='1`, co spowoduje wykonanie złośliwego zapytania SQL, zwracając wszystkie rekordy w tabeli.

---

### Skutki
- Nieautoryzowany dostęp do danych.
- Możliwość usunięcia, modyfikacji lub odczytania poufnych danych.
- Potencjalne przejęcie kontroli nad bazą danych.

---

### Zalecenia
1. **Użycie zapytań z parametrami (Prepared Statements)**:
   ```java
   @Repository
   public interface UserRepository extends JpaRepository<User, Long> {

       @Query("SELECT u FROM User u WHERE u.username = :username")
       List<User> findByUsername(@Param("username") String username);
   }
   ```

   **Dlaczego bezpieczne?**  
   - W Spring Data JPA parametry w zapytaniach są automatycznie escapowane, co zapobiega wstrzyknięciom SQL.

2. **Korzystanie z metod zapytań Spring Data JPA**:
   ```java
   @Repository
   public interface UserRepository extends JpaRepository<User, Long> {

       // Metoda zapytania generowana automatycznie na podstawie nazwy metody
       List<User> findByUsername(String username);
   }
   ```

   **Dlaczego bezpieczne?**  
   - Spring Data JPA automatycznie generuje zapytania SQL z użyciem parametrów, eliminując ryzyko SQL Injection.

---

### Mechanizmy Spring Security
1. **Walidacja danych wejściowych**:
   - Używaj adnotacji takich jak `@Pattern` lub `@Size` do walidacji danych wejściowych:
     ```java
     @RestController
     public class UserController {

         @GetMapping("/users")
         public List<User> getUsers(@RequestParam @Pattern(regexp = "^[a-zA-Z0-9]*$") String username) {
             return userRepository.findByUsername(username);
         }
     }
     ```

     **Dlaczego bezpieczne?**  
     - Walidacja ogranicza dane wejściowe do akceptowalnych wartości.

2. **Monitorowanie i rejestrowanie aktywności bazy danych**:
   - Użycie mechanizmów monitorowania zapytań, takich jak Hibernate Envers lub logi bazy danych, aby wykryć nietypowe wzorce zapytań.

3. **Użycie ORM (Object-Relational Mapping)**:
   - Korzystaj z JPA i Hibernate zamiast natywnych zapytań SQL. ORM zapewnia domyślne zabezpieczenia przed SQL Injection.

</details>

## A04:2021 Insecure Design

<details>
<summary>🔴 1. Open Redirect</summary>

### Opis
Open Redirect to podatność, która pozwala atakującemu na przekierowanie użytkownika na zewnętrzną, złośliwą stronę internetową. W Springu problem ten może wystąpić, jeśli aplikacja używa przekierowań na podstawie danych wejściowych użytkownika bez odpowiedniej walidacji lub ograniczeń.

---

### Przykład podatności
```java
@RestController
public class RedirectController {

    @GetMapping("/redirect")
    public ResponseEntity<Void> redirect(@RequestParam String url) {
        // Niebezpieczne przekierowanie na adres URL dostarczony przez użytkownika
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(url))
                .build();
    }
}
```

**Dlaczego podatny?**  
- Użytkownik może dostarczyć złośliwy adres URL, np. `http://malicious-site.com`, który zostanie użyty do przekierowania ofiary.
- Aplikacja nie weryfikuje, czy adres URL jest zaufany.

---

### Skutki
- Przekierowanie użytkownika na złośliwe strony internetowe.
- Kradzież danych uwierzytelniających (phishing).

---

### Zalecenia
1. **Ograniczenie przekierowań do zaufanych domen**:
   ```java
   @RestController
   public class RedirectController {

       private static final List<String> TRUSTED_DOMAINS = List.of("example.com", "trusted.com");

       @GetMapping("/redirect")
       public ResponseEntity<Void> redirect(@RequestParam String url) {
           URI uri = URI.create(url);

           // Weryfikacja, czy domena jest zaufana
           if (TRUSTED_DOMAINS.stream().noneMatch(uri.getHost()::endsWith)) {
               return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
           }

           return ResponseEntity.status(HttpStatus.FOUND)
                   .location(uri)
                   .build();
       }
   }
   ```

   **Dlaczego bezpieczne?**  
   - Przekierowanie odbywa się tylko do zaufanych domen.
   - Blokuje możliwość użycia niezaufanych adresów URL.

---

### Mechanizmy Spring Security
1. **Włączenie nagłówków zabezpieczających przekierowania**:
   - Spring Security automatycznie ustawia nagłówki takie jak `X-Content-Type-Options` i `X-Frame-Options`, które mogą pomóc w ochronie przed złośliwymi przekierowaniami.

2. **Filtrowanie danych wejściowych**:
   - Można zastosować adnotacje `@Valid` oraz `@Pattern`, aby ograniczyć potencjalnie złośliwe dane wejściowe.


</details>

<details>
<summary>🔴 2. Login Rate Limiting</summary>

### Opis
Brak mechanizmu ograniczania liczby żądań (rate limiting) w aplikacji może prowadzić do ataków typu brute force lub denial of service (DoS). W Spring REST API problem ten występuje, gdy aplikacja nie weryfikuje, ile żądań logowania pochodzi od konkretnego klienta w określonym czasie.

---

### Przykład podatności
```java
@RestController
public class LoginController {

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestParam String username, @RequestParam String password) {
        // Brak ograniczenia liczby prób logowania
        boolean success = authenticate(username, password);
        return success ? ResponseEntity.ok("Login successful") : ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    private boolean authenticate(String username, String password) {
        // Prosta weryfikacja logowania
        return "user".equals(username) && "password".equals(password);
    }
}
```

**Dlaczego podatny?**  
- Atakujący może wysyłać nieograniczoną liczbę żądań logowania, próbując odgadnąć dane uwierzytelniające.
- Brak jakichkolwiek mechanizmów rate limiting pozwala na wykorzystanie zasobów serwera, co może prowadzić do ataku DoS.

---

### Skutki
- Możliwość przeprowadzenia skutecznych ataków brute force.
- Obciążenie serwera i ograniczenie dostępności usługi (atak DoS).
- Naruszenie bezpieczeństwa użytkowników.

---

### Zalecenia
1. **Wprowadzenie limitu liczby żądań (Rate Limiting)**:
   - Użyj biblioteki takiej jak Bucket4j, aby ograniczyć liczbę żądań:
     ```java
     @RestController
     public class LoginController {

         private final Bucket bucket = Bucket4j.builder()
                 .addLimit(Bandwidth.simple(5, Duration.ofMinutes(1))) // 5 żądań na minutę
                 .build();

         @PostMapping("/login")
         public ResponseEntity<String> login(@RequestParam String username, @RequestParam String password) {
             if (!bucket.tryConsume(1)) {
                 return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body("Too many login attempts. Please try again later.");
             }

             boolean success = authenticate(username, password);
             return success ? ResponseEntity.ok("Login successful") : ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
         }

         private boolean authenticate(String username, String password) {
             return "user".equals(username) && "password".equals(password);
         }
     }
     ```

     **Dlaczego bezpieczne?**  
     - Mechanizm Bucket4j ogranicza liczbę żądań w określonym czasie, chroniąc przed brute force i DoS.

2. **Blokowanie użytkowników po określonej liczbie nieudanych prób**:
   - Dodaj funkcjonalność blokady konta po określonej liczbie nieudanych prób logowania:
     ```java
     @Service
     public class LoginAttemptService {

         private final Map<String, Integer> loginAttempts = new ConcurrentHashMap<>();
         private static final int MAX_ATTEMPTS = 5;

         public void loginFailed(String username) {
             loginAttempts.put(username, loginAttempts.getOrDefault(username, 0) + 1);
         }

         public boolean isBlocked(String username) {
             return loginAttempts.getOrDefault(username, 0) >= MAX_ATTEMPTS;
         }
     }
     ```

     **Dlaczego bezpieczne?**  
     - Zapobiega nieograniczonej liczbie prób logowania, blokując użytkowników po określonej liczbie nieudanych prób.

3. **Dodanie reCAPTCHA do procesu logowania**:
   - Po określonej liczbie prób logowania dodaj weryfikację CAPTCHA.


---

### Mechanizmy Spring Security
1. **Rate limiting przy użyciu SecurityFilterChain**:
   - Możesz dodać filtr ograniczający liczbę żądań:
     ```java
     @Configuration
     public class SecurityConfig {

         @Bean
         public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
             http
                 .addFilterBefore(new RateLimitingFilter(), UsernamePasswordAuthenticationFilter.class);
             return http.build();
         }
     }

     public class RateLimitingFilter extends GenericFilterBean {

         private final Bucket bucket = Bucket4j.builder()
                 .addLimit(Bandwidth.simple(5, Duration.ofMinutes(1))) // 5 żądań na minutę
                 .build();

         @Override
         public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
             if (!bucket.tryConsume(1)) {
                 ((HttpServletResponse) response).setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                 return;
             }
             chain.doFilter(request, response);
         }
     }
     ```

     **Dlaczego bezpieczne?**  
     - Filtr ogranicza liczbę żądań na poziomie warstwy zabezpieczeń Spring Security.


</details>

## A05:2021 Security Misconfiguration

<details>
<summary>🔴 1. Token/Cookie no expire </summary>

### Opis
Podatność występuje, gdy tokeny JWT lub ciasteczka sesyjne są generowane bez ustawionego czasu wygaśnięcia (`expiration time`) lub zbyt długim czasem ważności. W przypadku JWT brak pola `exp` w payloadzie, a w przypadku ciasteczek brak atrybutów `Expires` lub `Max-Age`. Tokeny takie pozostają ważne bezterminowo, co stanowi poważne zagrożenie bezpieczeństwa w przypadku ich przechwycenia.

---

### Przykład podatności
```java
public String generateToken(String username) {
    // Token JWT bez ustawionego czasu wygaśnięcia
    return Jwts.builder()
            .setSubject(username)
            .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
            .compact();
}
```

**Dlaczego podatny?**  
- Brak ustawionego pola `exp` powoduje, że token pozostaje ważny bezterminowo.
- W przypadku przechwycenia tokenu atakujący może używać go bez ograniczeń.

---

### Skutki
- **Przechwycone tokeny/cookie mogą być używane bezterminowo.**
- **Brak możliwości wymuszenia ponownego logowania.**
- **Zwiększone ryzyko ataków związanych z kradzieżą sesji.**
- **Problemy z unieważnieniem sesji po zmianie uprawnień użytkownika.**

---

### Zalecenia
1. **Ustawienie daty wygaśnięcia w tokenach JWT**:
   ```java
   public String generateToken(String username) {
       Date now = new Date();
       Date expiryDate = new Date(now.getTime() + 3600000); // 1 godzina

       return Jwts.builder()
               .setSubject(username)
               .setIssuedAt(now)
               .setExpiration(expiryDate) // Dodaj czas wygaśnięcia
               .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
               .compact();
   }
   ```

   **Dlaczego bezpieczne?**  
   - Token automatycznie traci ważność po określonym czasie, co minimalizuje ryzyko jego nadużycia.

2. **Ustawienie daty wygaśnięcia dla ciasteczek**:
   ```java
   @RestController
   public class CookieController {

       @PostMapping("/set-cookie")
       public ResponseEntity<Void> setCookie(HttpServletResponse response) {
           Cookie cookie = new Cookie("sessionId", "randomSessionValue");
           cookie.setHttpOnly(true);
           cookie.setSecure(true);
           cookie.setMaxAge(3600); // Czas wygaśnięcia 1 godzina
           response.addCookie(cookie);
           return ResponseEntity.ok().build();
       }
   }
   ```

   **Dlaczego bezpieczne?**  
   - Ogranicza czas życia ciasteczka, zmniejszając ryzyko jego wykorzystania w przypadku przechwycenia.

3. **Unieważnienie tokenów po zmianie uprawnień**:
   - Użyj bazy danych lub systemu zarządzania sesjami, aby przechowywać aktywne tokeny i weryfikować ich ważność.

4. **Regularne odświeżanie tokenów (Refresh Tokens)**:
   - Wprowadź mechanizm odświeżania tokenów, aby ograniczyć czas życia tokenów dostępowych.
  
### Mechanizmy Spring Security
1. **Automatyczne zarządzanie sesjami**:
   - Spring Security zapewnia automatyczne zarządzanie sesjami, co umożliwia wymuszanie wygasania sesji:
     ```java
     @Configuration
     public class SecurityConfig {

         @Bean
         public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
             http.sessionManagement()
                     .invalidSessionUrl("/login?expired=true")
                     .maximumSessions(1) // Ograniczenie do jednej aktywnej sesji na użytkownika
                     .expiredUrl("/login?expired=true"); // Przekierowanie po wygaśnięciu sesji
             return http.build();
         }
     }
     ```

   **Dlaczego bezpieczne?**  
   - Pozwala ograniczyć liczbę aktywnych sesji dla jednego użytkownika i wymusza ich unieważnienie.

2. **Weryfikacja daty wygaśnięcia tokenów JWT**:
   - Zaimplementuj filtr weryfikujący datę wygaśnięcia tokenów:
     ```java
     @Component
     public class JwtAuthenticationFilter extends OncePerRequestFilter {

         @Override
         protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                 throws ServletException, IOException {
             String token = request.getHeader("Authorization");
             if (token != null && !isTokenExpired(token)) {
                 // Token ważny - kontynuacja przetwarzania
             } else {
                 response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
             }
             chain.doFilter(request, response);
         }

         private boolean isTokenExpired(String token) {
             Claims claims = Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
             return claims.getExpiration().before(new Date());
         }
     }
     ```

   **Dlaczego bezpieczne?**  
   - Uniemożliwia używanie tokenów po ich wygaśnięciu, wymuszając ponowne logowanie.


</details>

<details>
<summary>🔴 2. Distributed Denial of Service (DDoS)</summary>

### Opis
Ataki typu Distributed Denial of Service (DDoS) polegają na zalewaniu serwera ogromną liczbą żądań z wielu źródeł, co powoduje wyczerpanie zasobów i brak dostępności usługi dla normalnych użytkowników. W kontekście Spring Framework ochrona przed DDoS może być realizowana poprzez różne techniki, takie jak filtrowanie ruchu, dynamiczne blokowanie adresów IP oraz ograniczanie przepustowości.

---

### Przykład podatności
```java
@RestController
public class ExampleController {

    @GetMapping("/data")
    public ResponseEntity<String> fetchData() {
        // Brak ograniczeń liczby żądań, co pozwala na zalewanie serwera
        return ResponseEntity.ok("Data fetched successfully");
    }
}
```

**Dlaczego podatny?**  
- Brak jakiegokolwiek mechanizmu kontrolującego liczbę żądań lub ich źródło.
- Atakujący może wysyłać nieograniczoną liczbę żądań, co prowadzi do przeciążenia serwera.

---

### Skutki
- Niedostępność usługi dla normalnych użytkowników.
- Wyczerpanie zasobów serwera, takich jak CPU, pamięć czy przepustowość sieci.
- Potencjalne zwiększenie kosztów operacyjnych (np. w modelach chmurowych).

---

### Zalecenia
1. **Implementacja dynamicznego filtrowania ruchu**:
   - Przykład kodu dynamicznie ograniczającego liczbę żądań z tego samego adresu IP:
     ```java
     @Component
     @Order(1)
     public class RateLimitFilter implements Filter {

         private final ConcurrentHashMap<String, AtomicLong> requestCount = new ConcurrentHashMap<>();
         private final long rateLimit = 10; // Maksymalna liczba żądań na okres czasu

         @Override
         public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
             String ipAddress = request.getRemoteAddr();
             AtomicLong count = requestCount.computeIfAbsent(ipAddress, k -> new AtomicLong());

             // Sprawdzenie, czy liczba żądań przekracza limit
             if (count.incrementAndGet() > rateLimit) {
                 HttpServletResponse httpResponse = (HttpServletResponse) response;
                 httpResponse.setStatus(HttpServletResponse.SC_TOO_MANY_REQUESTS);
                 httpResponse.getWriter().write("Rate limit exceeded. Please try again later.");
                 return;
             }

             chain.doFilter(request, response);
         }
     }
     ```

     **Dlaczego bezpieczne?**  
     - Działa na poziomie filtrów HTTP, rejestrując liczbę żądań na podstawie adresu IP.
     - Blokuje adresy IP, które przekroczą zdefiniowany limit żądań.

---

### Mechanizmy Spring Security

1. **Konfiguracja timeoutów w Spring Boot**:
   - Ustaw odpowiednie timeouty dla żądań HTTP:
     ```properties
     server.connection-timeout=5000
     spring.mvc.async.request-timeout=5000
     ```

     **Dlaczego bezpieczne?**  
     - Ogranicza czas przetwarzania żądań, co zapobiega blokowaniu zasobów przez długotrwałe żądania.

</details>

<details>
<summary>🔴 3. TLS force/HSTS</summary>

### Opis
TLS (Transport Layer Security) zapewnia szyfrowanie danych przesyłanych pomiędzy klientem a serwerem, chroniąc je przed przechwyceniem (np. w atakach typu Man-in-the-Middle). Brak wymuszania TLS lub brak nagłówka HSTS (HTTP Strict Transport Security) w odpowiedziach HTTP może pozwolić na przesyłanie danych w sposób niezaszyfrowany, co stanowi zagrożenie dla bezpieczeństwa aplikacji.

---

### Przykład podatności
```java
@RestController
public class ExampleController {

    @GetMapping("/data")
    public ResponseEntity<String> fetchData() {
        // Brak zabezpieczenia transmisji TLS
        return ResponseEntity.ok("Sensitive data");
    }
}
```

**Dlaczego podatny?**  
- Jeśli aplikacja dopuszcza komunikację za pomocą HTTP zamiast HTTPS, dane są przesyłane w sposób niezaszyfrowany.
- Brak nagłówka HSTS umożliwia ataki typu downgrade, w których użytkownik jest przekierowany do nieszyfrowanej wersji aplikacji.

---

### Skutki
- Możliwość przechwycenia wrażliwych danych przez atakujących.
- Ataki typu Man-in-the-Middle (MITM) i downgrade protokołu.
- Naruszenie poufności danych użytkowników.

---

### Zalecenia
1. **Wymuszenie HTTPS w konfiguracji Spring Security**:
   - Skonfiguruj `HttpSecurity`, aby wymusić HTTPS:
     ```java
     @Configuration
     public class SecurityConfig {

         @Bean
         public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
             http.requiresChannel()
                 .anyRequest()
                 .requiresSecure(); // Wymusza HTTPS na wszystkich żądaniach
             return http.build();
         }
     }
     ```

     **Dlaczego bezpieczne?**  
     - Zapewnia, że wszystkie żądania są przesyłane przez HTTPS, eliminując możliwość przesyłania danych w sposób niezaszyfrowany.

2. **Dodanie nagłówka HSTS**:
   - Konfiguracja Spring Security, aby automatycznie dodawać nagłówek HSTS:
     ```java
     @Configuration
     public class SecurityConfig {

         @Bean
         public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
             http.headers()
                 .httpStrictTransportSecurity()
                 .includeSubDomains(true)
                 .maxAgeInSeconds(31536000); // 1 rok
             return http.build();
         }
     }
     ```

     **Dlaczego bezpieczne?**  
     - HSTS wymusza, aby przeglądarka zawsze korzystała z HTTPS, nawet jeśli użytkownik ręcznie wpisze adres HTTP.

3. **Konfiguracja SSL/TLS w Spring Boot**:
   - Skonfiguruj certyfikat SSL w `application.properties`:
     ```properties
     server.ssl.key-store=classpath:keystore.p12
     server.ssl.key-store-password=yourPassword
     server.ssl.key-store-type=PKCS12
     server.port=8443
     ```

     **Dlaczego bezpieczne?**  
     - Certyfikat SSL/TLS zapewnia szyfrowanie transmisji danych między klientem a serwerem.

4. **Przekierowanie HTTP do HTTPS**:
   - Dodaj regułę przekierowania w serwerze aplikacji (np. Tomcat, Nginx) lub konfiguracji Spring Boot:
     ```java
     @Configuration
     public class HttpToHttpsRedirectConfig {

         @Bean
         public WebServerFactoryCustomizer<TomcatServletWebServerFactory> redirectConfig() {
             return factory -> factory.addAdditionalTomcatConnectors(httpToHttpsRedirectConnector());
         }

         private Connector httpToHttpsRedirectConnector() {
             Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
             connector.setScheme("http");
             connector.setPort(8080);
             connector.setSecure(false);
             connector.setRedirectPort(8443);
             return connector;
         }
     }
     ```

     **Dlaczego bezpieczne?**  
     - Automatycznie przekierowuje użytkowników korzystających z HTTP do HTTPS, eliminując ryzyko przesyłania danych w sposób niezaszyfrowany.

5. **Monitorowanie protokołu TLS**:
   - Regularnie weryfikuj używane wersje TLS (zaleca się korzystanie z TLS 1.2 lub nowszego).

---

### Mechanizmy Spring Security
1. **Włączenie nagłówków zabezpieczających**:
   - Spring Security automatycznie dodaje nagłówki zabezpieczające, takie jak `Strict-Transport-Security`, `X-Content-Type-Options`, i `X-Frame-Options`, zwiększając ochronę aplikacji.

2. **Obsługa certyfikatów klienta**:
   - Spring Security umożliwia wymuszanie uwierzytelniania TLS na podstawie certyfikatów klienta w konfiguracji.


</details>

<details>
<summary>🔴 4. Debug Mode Enabled</summary>

### Opis
Debug Mode to tryb diagnostyczny, który ujawnia szczegółowe informacje o aplikacji, takie jak konfiguracja serwera, stacktrace, szczegóły bazy danych czy dane środowiskowe. Włączenie trybu debugowania w środowisku produkcyjnym stanowi poważne zagrożenie bezpieczeństwa, ponieważ te informacje mogą być wykorzystane przez atakujących.

---

### Przykład podatności
```java
@RestController
@ControllerAdvice
public class DebugController {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception ex) {
        // Wyświetlanie pełnego stacktrace w odpowiedzi
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ex.toString());
    }

    @GetMapping("/debug")
    public ResponseEntity<String> debugEndpoint() {
        // Ujawnienie szczegółowych informacji o serwerze
        return ResponseEntity.ok("Debug Mode Enabled: Environment = " + System.getenv());
    }
}
```

**Dlaczego podatny?**  
- Wyświetlanie stacktrace i danych środowiskowych ujawnia szczegóły implementacji aplikacji i serwera.
- Atakujący może wykorzystać te informacje do przeprowadzenia dalszych ataków, takich jak SQL Injection, RCE lub inne.

---

### Skutki
- Ujawnienie poufnych informacji o systemie, takich jak zmienne środowiskowe, dane bazy danych, wersje bibliotek czy szczegóły konfiguracji.
- Możliwość wykorzystania tych informacji przez atakujących do przeprowadzenia dalszych ataków.
- Naruszenie zasad bezpieczeństwa danych.

---

### Zalecenia
1. **Wyłącz debug mode w środowisku produkcyjnym**:
   - W pliku `application.properties` lub `application.yml` ustaw debugowanie jako wyłączone:
     ```properties
     spring.devtools.restart.enabled=false
     spring.main.banner-mode=off
     ```

     **Dlaczego bezpieczne?**  
     - Zapobiega wyświetlaniu szczegółowych informacji diagnostycznych w środowisku produkcyjnym.


2. **Testowanie w środowisku testowym**:
   - Debug mode może być używany wyłącznie w środowisku testowym lub deweloperskim poprzez różnicowanie konfiguracji:
     ```properties
     # application-dev.properties
     spring.devtools.restart.enabled=true
     spring.main.banner-mode=console

     # application-prod.properties
     spring.devtools.restart.enabled=false
     spring.main.banner-mode=off
     ```

---

### Mechanizmy Spring Security
1. **Kontrola dostępu do endpointów diagnostycznych**:
   - Ogranicz dostęp do wrażliwych endpointów (np. /actuator) wyłącznie dla administratorów:
     ```java
     @Configuration
     public class SecurityConfig {

         @Bean
         public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
             http.authorizeRequests()
                 .antMatchers("/actuator/**").hasRole("ADMIN") // Tylko dla administratorów
                 .anyRequest().authenticated();
             return http.build();
         }
     }
     ```

     **Dlaczego bezpieczne?**  
     - Uniemożliwia nieautoryzowanym użytkownikom dostęp do wrażliwych danych diagnostycznych.

2. **Ukrycie szczegółowych informacji o błędach**:
   - W Spring Security możesz włączyć niestandardową stronę błędu:
     ```java
     @Configuration
     public class SecurityConfig {

         @Bean
         public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
             http.exceptionHandling()
                 .accessDeniedPage("/error/access-denied");
             return http.build();
         }
     }
     ```

     **Dlaczego bezpieczne?**  
     - Zapewnia, że szczegóły błędów są ukryte przed użytkownikiem.

</details>

## A09:2021 Security Logging and Monitoring Failures
<details>
<summary>Wprowadzenie do logowania w Spring Framework</summary>
    
### Spring Framework domyślnie obsługuje logowanie za pomocą popularnych bibliotek takich jak SLF4J i Logback. Logi są zapisywane w konsoli lub w plikach, w zależności od konfiguracji. Aby włączyć logowanie do plików, wystarczy skonfigurować `application.properties` lub `logback.xml`.

#### Domyślne ustawienia logowania
Spring Boot ma wbudowaną konfigurację logowania, która zapisuje logi na poziomie `INFO`. W aplikacji Spring Boot logi można znaleźć w konsoli, chyba że skonfigurowano je do zapisywania w pliku.

#### Przykład konfiguracji logowania
1. **Logi w pliku za pomocą `application.properties`:**
   ```properties
   logging.file.name=app.log  # Ścieżka do pliku z logami
   logging.level.root=INFO    # Poziom logowania (DEBUG, INFO, WARN, ERROR)
   logging.pattern.console=%d{yyyy-MM-dd HH:mm:ss} - %msg%n
   logging.pattern.file=%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n
   ```

2. **Konfiguracja za pomocą `logback.xml`:**
   ```xml
   <configuration>
       <appender name="FILE" class="ch.qos.logback.core.FileAppender">
           <file>app.log</file>
           <encoder>
               <pattern>%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n</pattern>
           </encoder>
       </appender>
       <root level="INFO">
           <appender-ref ref="FILE" />
       </root>
   </configuration>
   ```
#### W Javie istnieje możliwość logowania za pomocą wbudowanej klasy java.util.logging.Logger, która jest częścią standardowej biblioteki Javy. Jednak w nowoczesnych aplikacjach rzadko używa się tej metody, ponieważ oferuje ograniczone możliwości w porównaniu z popularnymi bibliotekami logowania, takimi jak SLF4J, Logback czy Log4j. 
</details>

<details>
<summary>🔴 1. Password in Logs</summary>

### Opis
Zapisanie hasła w logach może prowadzić do naruszenia bezpieczeństwa, jeśli logi dostaną się w niepowołane ręce. Może to być efektem logowania pełnych treści żądań lub odpowiedzi HTTP, które zawierają dane uwierzytelniające.

---

### Przykład podatności
```java
@PostMapping("/login")
public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest) {
    log.info("User attempting login with password: {}", loginRequest.getPassword());
    return ResponseEntity.ok("Login successful");
}
```

**Dlaczego podatny?**  
- Logowanie hasła wprost w logach powoduje, że dane uwierzytelniające są widoczne dla osób z dostępem do plików logów.

---

### Zalecenia
1. **Unikaj logowania danych uwierzytelniających**:
   ```java
   log.info("User attempting login with username: {}", loginRequest.getUsername());
   ```

2. **Maskowanie poufnych danych**:
   - Użyj maskowania, aby ukryć hasło:
     ```java
     log.info("User attempting login with password: *****");
     ```

---

</details>

<details>
<summary>🔴 2. Logging Enabled</summary>

### Opis
Brak włączonego logowania lub niewystarczające logowanie może utrudnić wykrywanie incydentów bezpieczeństwa. Logowanie powinno być zawsze włączone w środowisku produkcyjnym, z odpowiednio dobranym poziomem logowania.

---

### Przykład podatności
- Brak logowania zdarzeń związanych z bezpieczeństwem, takich jak nieudane próby logowania, zmiany uprawnień czy podejrzane operacje.

---

### Zalecenia
1. **Włącz logowanie zdarzeń krytycznych**:
   - Loguj zdarzenia takie jak próby logowania, zmiany danych użytkownika czy błędy aplikacji:
     ```java
     log.warn("Failed login attempt for user: {}", username);
     log.info("User {} changed their password", username);
     ```

2. **Korzystaj z odpowiedniego poziomu logowania**:
   - Ustaw poziom logowania na `INFO` lub `WARN` dla zdarzeń krytycznych.

---

</details>

<details>
<summary>🔴 3. No Logs Exposed to User</summary>

### Opis
Eksponowanie logów użytkownikowi może ujawnić wrażliwe informacje o systemie, takie jak stacktrace, szczegóły implementacji czy inne dane diagnostyczne.

---

### Przykład podatności
```java
@ExceptionHandler(Exception.class)
public ResponseEntity<String> handleException(Exception ex) {
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ex.toString());
}
```

**Dlaczego podatny?**  
- Użytkownik otrzymuje pełny stacktrace, który może ujawnić szczegóły implementacji aplikacji.

---

### Zalecenia
1. **Unikaj ujawniania logów użytkownikowi**:
   ```java
   @ExceptionHandler(Exception.class)
   public ResponseEntity<String> handleException(Exception ex) {
       return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An unexpected error occurred.");
   }
   ```

2. **Użyj centralnego systemu logowania**:
   - Przechowuj logi w bezpiecznym miejscu, niedostępnym dla użytkowników końcowych.

---

</details>

## A10:2021 Server Side Request Forgery (SSRF)

<details>
<summary>Server Side Request Forgery (SSRF)</summary>

### Opis ogólny podatności
Server Side Request Forgery (SSRF) to podatność umożliwiająca atakującemu zmuszenie serwera aplikacyjnego do wykonania nieautoryzowanego żądania HTTP. Atakujący może wykorzystać podatność do uzyskania dostępu do wewnętrznych zasobów serwera, takich jak bazy danych, API lub panele administracyjne. Problem pojawia się, gdy serwer wykonuje żądania HTTP na podstawie danych wejściowych użytkownika bez odpowiedniej walidacji.

---

### Potencjalne skutki
- **Nieautoryzowany dostęp do wewnętrznych zasobów serwera**: możliwość odczytu lub modyfikacji danych.
- **Wykorzystanie serwera jako pośrednika**: atakujący może używać serwera aplikacyjnego do przeprowadzania ataków na inne systemy.
- **Skuteczne ataki na metadane instancji chmurowych**: w środowiskach chmurowych (np. AWS, Azure), SSRF może prowadzić do wycieku kluczy API lub innych danych uwierzytelniających.

---

### Zalecenia dla frameworka
1. **Walidacja danych wejściowych**:
   - Używaj białej listy zaufanych domen lub wzorców URL, aby ograniczyć źródła żądań.
   - Sprawdzaj, czy żądania nie są kierowane do wewnętrznych adresów IP (np. `127.0.0.1`, `169.254.x.x`).

2. **Ograniczenie uprawnień serwera**:
   - Konfiguruj uprawnienia sieciowe tak, aby serwer aplikacyjny nie miał dostępu do wrażliwych zasobów wewnętrznych.

3. **Monitorowanie i logowanie**:
   - Rejestruj wszystkie żądania HTTP, szczególnie te inicjowane przez serwer, aby wykrywać podejrzane działania.

4. **Ograniczenie możliwości korzystania z dynamicznych żądań HTTP**:
   - Jeśli aplikacja nie wymaga dynamicznego tworzenia żądań HTTP na podstawie danych użytkownika, rozważ ich całkowite wyłączenie.

5. **Regularne testowanie bezpieczeństwa**:
   - Wdrażaj testy bezpieczeństwa w procesie CI/CD, aby identyfikować i eliminować podatności związane z SSRF.

</details>

