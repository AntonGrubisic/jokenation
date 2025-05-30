package se.iths.jokeservice;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Random;

@RestController
@PreAuthorize("hasAnyAuthority('SCOPE_jokes.read')")
@RequestMapping("/jokes")
public class JokeController {

    private final List<String> jokes = List.of(
            "Why did the Java developer teach his young kids about single quotes? Because they build character."
    );

    @GetMapping
    @PreAuthorize("hasAnyAuthority('SCOPE_jokes.read')")
    public List<String> getJokes() {
        return jokes;
    }

    @GetMapping("/random")
    @PreAuthorize("hasAuthority('SCOPE_jokes.read')")
    public String getRandomJoke() {
        Random random = new Random();
        return jokes.get(random.nextInt(jokes.size()));
    }
}
