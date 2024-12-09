
# OWASP Top 10 (2021) - Spring Framework

## A01:2021 Broken Access Control

<details>
<summary> 🔴 1. Zagrożenia związane z lokalnym włączeniem plików (Local File Inclusion, LFI)</summary>

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
<summary> 🔴 2. Zagrożenia związane z dostępem do obiektów poprzez middleware (Object access middleware)</summary>

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
<summary>3. Zagrożenia związane z masowym przypisywaniem (Mass Assignment)</summary>

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
