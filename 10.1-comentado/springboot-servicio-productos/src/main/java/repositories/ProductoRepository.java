package repositories;

import com.formacionbdi.springboot.app.productos.models.entity.Producto;
import org.springframework.context.annotation.Bean;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;


public interface ProductoRepository extends CrudRepository<Producto, Long> {
    ArrayList<Producto> findByUsuario(String usuario);
}
