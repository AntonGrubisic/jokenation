package se.iths.quoteservice;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Random;

@RestController
@PreAuthorize("hasAnyAuthority('SCOPE_quotes.read')")
@RequestMapping("/quotes")
public class QuoteController {

    private final List<String> quotes = List.of(
            "Never argue with an idiot. They will drag you down to their level and beat you with experience"
    );

    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_quotes.read')")
    public List<String> getQuotes() {
        return quotes;
    }

    @GetMapping("/random")
    @PreAuthorize("hasAuthority('SCOPE_quotes.read')")
    public String getRandomQuote() {
        Random random = new Random();
        return quotes.get(random.nextInt(quotes.size()));
    }
}
